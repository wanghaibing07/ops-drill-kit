from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, replace
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))

import mysql_lifecycle_candidate as lifecycle
from test_mysql_gates import FIRST, SECOND, UPDATED
import test_mysql_live_identity as identity_tests
RID = identity_tests.RID


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        base = identity_tests.LiveIdentityTests()
        base.setUp()
        source = base.record
        target = replace(source, label='target', server_uuid=base.state['uuids']['target'],
                         unit=lifecycle.ctl.unit(RID, 'target'), argv=tuple(lifecycle.ctl.command(RID, 'target')),
                         control_group='/system.slice/' + lifecycle.ctl.unit(RID, 'target'))
        self.state = base.state
        self.state.update({'version': 1, 'phase': 'READY', 'lifecycle_version': lifecycle.VERSION,
                           'candidate_phase': 'FAULT', 'deadline_boottime': 999,
                           'candidate_identities': {'source': asdict(source), 'target': asdict(target)},
                           'backup_start': ['pitr-bin.000002', 158], 'backup_after': ['pitr-bin.000002', 158],
                           'replay_stop': ['pitr-bin.000002', 584], 'fault_end': ['pitr-bin.000002', 945],
                           'fixture': {'baseline': [list(FIRST), list(SECOND)],
                                       'before_delete': [list(UPDATED), list(SECOND)]}, 'binlog_sha256': 'a'*64})
        for rec in self.state['candidate_identities'].values():
            rec['argv'] = list(rec['argv'])

    def test_identity_accepts_memory_tuple_and_json_list(self):
        with patch.object(lifecycle.live, 'check'):
            self.assertEqual(set(lifecycle.records_from_state(RID, self.state)), {'source', 'target'})
            for rec in self.state['candidate_identities'].values():
                rec['argv'] = tuple(rec['argv'])
            self.assertEqual(set(lifecycle.records_from_state(RID, self.state)), {'source', 'target'})

    def test_fault_and_recovery_are_independently_observed(self):
        with patch.object(lifecycle.drill, 'rows', side_effect=[[UPDATED], [list(FIRST), list(SECOND)]]):
            self.assertEqual(lifecycle.check_data(RID, self.state), 'FAULT')
        self.state['candidate_phase'] = 'RECOVERED'
        with patch.object(lifecycle.drill, 'rows', side_effect=[[UPDATED], [UPDATED, SECOND]]):
            self.assertEqual(lifecycle.check_data(RID, self.state), 'RECOVERED')
        with patch.object(lifecycle.drill, 'rows', side_effect=[[UPDATED], [FIRST, SECOND]]):
            with self.assertRaises(lifecycle.fixture.FixtureRejected):
                lifecycle.check_data(RID, self.state)

    def test_tampered_fixture_and_positions_are_rejected(self):
        self.state['fixture']['before_delete'][0][5] = '999'
        with self.assertRaises(lifecycle.fixture.FixtureRejected):
            lifecycle.evidence(self.state)
        self.state['fault_end'][1] = 584
        with self.assertRaises(lifecycle.ctl.SafetyError):
            lifecycle.positions(self.state)

    def test_reload_requires_complete_bound_identity(self):
        with patch.object(lifecycle.live, 'check'):
            records = lifecycle.records_from_state(RID, deepcopy(self.state))
        self.assertEqual(records['source'].argv, tuple(lifecycle.ctl.command(RID, 'source')))
        self.state['candidate_identities']['source']['label'] = 'target'
        with patch.object(lifecycle.live, 'check'), self.assertRaises(lifecycle.ctl.SafetyError):
            lifecycle.records_from_state(RID, self.state)

    def test_prepare_then_resolve_uses_closed_binlog_and_separate_checks(self):
        operations = []
        positions = iter([['pitr-bin.000002',158], ['pitr-bin.000002',158],
                          ['pitr-bin.000002',584], ['pitr-bin.000002',945], ['pitr-bin.000003',4]])
        @contextmanager
        def dump_gate(*args):
            yield 12, types.SimpleNamespace(sha256='dump-hash')
        @contextmanager
        def bin_gate(*args):
            operations.append('audit-binlog')
            yield 13, b'binlog', types.SimpleNamespace(sha256='a'*64)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            folder = Path(tmp)
            (folder/'synthetic-full.sql').write_bytes(b'dump')
            (folder/'pitr-bin.000002').write_bytes(b'binlog')
            source_rows = [[list(FIRST), list(SECOND)], [list(UPDATED), list(SECOND)],
                           [list(UPDATED)], [list(UPDATED)], [list(UPDATED)]]
            target_rows = [[list(FIRST), list(SECOND)], [list(FIRST), list(SECOND)],
                           [list(UPDATED), list(SECOND)]]
            def rows(rid, state, label):
                return (source_rows if label == 'source' else target_rows).pop(0)
            def query(rid, state, label, sql):
                if sql.startswith('UPDATE'): operations.append('update')
                if sql.startswith('DELETE'): operations.append('delete')
            with patch.object(lifecycle.drill.probe, 'verify_observers'), \
                 patch.object(lifecycle.drill.probe, 'query', side_effect=query), \
                 patch.object(lifecycle.drill.probe, 'position', side_effect=lambda *a: next(positions)), \
                 patch.object(lifecycle.drill.business, 'verify_schema_contract'), \
                 patch.object(lifecycle.drill, 'rows', side_effect=rows), \
                 patch.object(lifecycle.drill, 'capture_dump', return_value=folder/'synthetic-full.sql'), \
                 patch.object(lifecycle.drill.backup_gate, 'audited_dump_stream', dump_gate), \
                 patch.object(lifecycle.drill, 'import_dump', side_effect=lambda *a: operations.append('import')), \
                 patch.object(lifecycle.ctl, 'save'), patch.object(lifecycle.ctl, 'verify'), \
                 patch.object(lifecycle.ctl, 'paths', return_value=(folder, folder, folder/'mysql.sock')), \
                 patch.object(lifecycle.os, 'O_NOFOLLOW', getattr(lifecycle.os, 'O_NOFOLLOW', 0), create=True), \
                 patch.object(lifecycle.binlog, 'audited_binlog_stream', bin_gate), \
                 patch.object(lifecycle.drill, 'generate_replay', return_value=folder/'replay.sql'), \
                 patch.object(lifecycle.drill, 'restricted_replay', side_effect=lambda *a: operations.append('replay')):
                lifecycle.prepare_fault(RID, self.state, folder)
                self.assertEqual(self.state['candidate_phase'], 'FAULT')
                lifecycle.resolve_data(RID, self.state, folder)
                self.assertEqual(self.state['candidate_phase'], 'RECOVERED')
        self.assertEqual(operations, ['import','update','delete','audit-binlog','audit-binlog','replay'])

    def test_existing_commands_reload_state_and_retry_resolve(self):
        stored = deepcopy(self.state)
        @contextmanager
        def guard(*args):
            yield
        def load(*args):
            return deepcopy(stored)
        def resolve(rid, state, directory):
            state['candidate_phase'] = 'RECOVERED'
            stored.update(deepcopy(state))
        def check(rid, state):
            return state['candidate_phase']
        with patch.object(lifecycle.ctl, 'setup'), patch.object(lifecycle.ctl, 'secure_dir'), \
             patch.object(lifecycle.ctl, 'locked', return_value=99), patch.object(lifecycle.os, 'close'), \
             patch.object(lifecycle.ctl, 'load', side_effect=load), patch.object(lifecycle.ctl, 'require_same_boot', return_value=1), \
             patch.object(lifecycle, 'guarded', guard), patch.object(lifecycle, 'check_data', side_effect=check), \
             patch.object(lifecycle, 'resolve_data', side_effect=resolve) as apply:
            self.assertEqual(lifecycle.existing('check', RID)['status'], 'FAULT')
            self.assertEqual(lifecycle.existing('resolve', RID)['status'], 'RECOVERED')
            self.assertEqual(lifecycle.existing('resolve', RID)['status'], 'RECOVERED')
            self.assertEqual(lifecycle.existing('check', RID)['status'], 'RECOVERED')
            apply.assert_called_once()

    def test_interrupted_resolution_never_replays_again(self):
        self.state['candidate_phase'] = 'RESOLVING'
        with patch.object(lifecycle.ctl, 'setup'), patch.object(lifecycle.ctl, 'secure_dir'), \
             patch.object(lifecycle.ctl, 'locked', return_value=99), patch.object(lifecycle.os, 'close'), \
             patch.object(lifecycle.ctl, 'load', return_value=self.state), \
             patch.object(lifecycle.ctl, 'require_same_boot', return_value=1), \
             patch.object(lifecycle, 'resolve_data') as resolve:
            with self.assertRaises(lifecycle.ctl.SafetyError):
                lifecycle.existing('resolve', RID)
        resolve.assert_not_called()

    def test_resolve_rejects_changed_binlog_before_replay(self):
        @contextmanager
        def audited(*args):
            yield 11, b'log', types.SimpleNamespace(sha256='b'*64)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            logfile = Path(tmp) / 'pitr-bin.000002'
            logfile.write_bytes(b'log')
            with patch.object(lifecycle, 'check_data', return_value='FAULT'), \
                 patch.object(lifecycle.ctl, 'save'), patch.object(lifecycle.ctl, 'verify'), \
                 patch.object(lifecycle.ctl, 'paths', return_value=(Path(tmp), Path(tmp), None)), \
                 patch.object(lifecycle.os, 'O_NOFOLLOW', getattr(lifecycle.os, 'O_NOFOLLOW', 0), create=True), \
                 patch.object(lifecycle.binlog, 'audited_binlog_stream', audited), \
                 patch.object(lifecycle.drill, 'restricted_replay') as replay:
                with self.assertRaises(lifecycle.ctl.SafetyError):
                    lifecycle.resolve_data(RID, self.state, Path(tmp))
                replay.assert_not_called()
        self.assertEqual(self.state['candidate_phase'], 'RESOLVING')

    def test_reset_rejects_replaced_inactive_unit(self):
        self.state['candidate_stopped'] = ['target']
        def properties(name):
            if name.endswith('-init.service'):
                return {'LoadState': 'not-found', 'ActiveState': 'inactive'}
            return {'LoadState': 'loaded', 'ActiveState': 'inactive'}
        with patch.object(lifecycle.ctl, 'properties', side_effect=properties), \
             patch.object(lifecycle.ctl, 'run', return_value='InvocationID=' + 'f'*32), \
             patch.object(lifecycle.ctl, 'verify'), patch.object(lifecycle.ctl, 'stop_one') as stop:
            with self.assertRaises(lifecycle.ctl.SafetyError):
                lifecycle.reset_bound(RID, self.state, Path('.'))
            stop.assert_not_called()

    def test_reset_partial_retry_skips_confirmed_stopped_target(self):
        self.state['candidate_stopped'] = ['target']
        stops = []
        with patch.object(lifecycle.ctl, 'properties', return_value={'LoadState': 'not-found', 'ActiveState': 'inactive'}), \
             patch.object(lifecycle.os.path, 'lexists', return_value=False), \
             patch.object(lifecycle.ctl, 'verify') as verify, patch.object(lifecycle.ctl, 'save'), \
             patch.object(lifecycle.ctl, 'stop_one', side_effect=lambda rid, label: stops.append(label)):
            lifecycle.reset_bound(RID, self.state, Path('.'))
            self.assertEqual(stops, ['source'])
            self.assertEqual(self.state['candidate_phase'], 'STOPPED')
            verify.reset_mock()
            lifecycle.reset_bound(RID, self.state, Path('.'))
            verify.assert_not_called()
            self.assertEqual(stops, ['source'])

    def test_reset_rejects_missing_account_cleanup_or_unknown_stopped_socket(self):
        self.state['candidate_stopped'] = ['target']
        with patch.object(lifecycle.ctl, 'properties', return_value={'LoadState': 'not-found', 'ActiveState': 'inactive'}), \
             patch.object(lifecycle.os.path, 'lexists', return_value=True), \
             patch.object(lifecycle.ctl, 'verify'), patch.object(lifecycle.ctl, 'stop_one') as stop:
            with self.assertRaises(lifecycle.ctl.SafetyError):
                lifecycle.reset_bound(RID, self.state, Path('.'))
            stop.assert_not_called()
        self.state['import_account'] = {'name': 'pending'}
        with self.assertRaises(lifecycle.ctl.SafetyError):
            lifecycle.reset_bound(RID, self.state, Path('.'))

    def test_exit_codes_and_run_id_on_failure(self):
        with patch.object(lifecycle, 'start_run', side_effect=RuntimeError()), patch('builtins.print') as out:
            self.assertEqual(lifecycle.main(['start', RID]), 2)
            self.assertIn(RID, out.call_args.args[0])
        with patch.object(lifecycle, 'existing', return_value={'run_id': RID, 'status': 'FAULT'}), patch('builtins.print'):
            self.assertEqual(lifecycle.main(['check', RID]), 1)


if __name__ == '__main__':
    unittest.main()
