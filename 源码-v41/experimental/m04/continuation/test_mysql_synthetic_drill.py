from contextlib import contextmanager, ExitStack
import copy
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

PARENT = str(Path(__file__).resolve().parent.parent)
if PARENT not in sys.path:
    sys.path.insert(0, PARENT)
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))

import mysql_synthetic_drill as drill
from test_mysql_gates import FIRST, SECOND, UPDATED

RID = '0123456789abcdef'


class DrillTests(unittest.TestCase):
    def setUp(self):
        self.state = {'run_id': RID, 'primary_uuid': '0', 'uuids': {'source': 'a', 'target': 'b'},
                      'business_phase': 'TEST_ONLY'}

    def test_full_order_uses_backup_import_then_update_delete_and_replay(self):
        state = self.state
        actions = []
        source_rows = [[FIRST, SECOND], [FIRST, SECOND], [UPDATED, SECOND], [UPDATED], [UPDATED], [UPDATED, SECOND]]
        positions = [['pitr-bin.000001', 123], ['pitr-bin.000001', 123],
                     ['pitr-bin.000001', 234], ['pitr-bin.000001', 345], ['pitr-bin.000002', 4]]
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp, ExitStack() as stack:
            directory = Path(temp)
            dump = directory / 'dump'
            dump.write_bytes(b'dump')
            (directory / 'pitr-bin.000001').write_bytes(b'log')
            @contextmanager
            def dump_gate(fd, start, end):
                actions.append('audit-dump')
                yield fd, types.SimpleNamespace(sha256='dump-sha')
            @contextmanager
            def bin_gate(fd, start, stop, end):
                actions.append('audit-binlog')
                yield fd, b'binlog', types.SimpleNamespace(sha256='binlog-sha')
            stack.enter_context(patch.object(drill.probe, 'verify_observers'))
            stack.enter_context(patch.object(drill.business, 'verify_schema_contract'))
            stack.enter_context(patch.object(drill.ctl, 'verify'))
            stack.enter_context(patch.object(drill.ctl, 'paths', return_value=(directory, directory, 'socket')))
            stack.enter_context(patch.object(drill.probe, 'position', side_effect=positions))
            stack.enter_context(patch.object(drill.probe, 'query', side_effect=lambda *a: actions.append(a[-1])))
            stack.enter_context(patch.object(drill, 'rows', side_effect=source_rows))
            stack.enter_context(patch.object(drill, 'capture_dump', side_effect=lambda *a: actions.append('dump') or dump))
            stack.enter_context(patch.object(drill.backup_gate, 'audited_dump_stream', dump_gate))
            stack.enter_context(patch.object(drill.binlog_gate, 'audited_binlog_stream', bin_gate))
            stack.enter_context(patch.object(drill, 'import_dump', side_effect=lambda *a: actions.append('import')))
            stack.enter_context(patch.object(drill, 'generate_replay', side_effect=lambda *a: actions.append('mysqlbinlog') or 'replay'))
            stack.enter_context(patch.object(drill, 'restricted_replay', side_effect=lambda *a: actions.append('replay')))
            stack.enter_context(patch.object(drill, 'phase', side_effect=lambda d, s, p: actions.append('phase:' + p)))
            stack.enter_context(patch.object(drill.ctl, 'save'))
            # O_NOFOLLOW is a Linux requirement. This test uses ordinary local files on Windows.
            stack.enter_context(patch.object(drill.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True))
            drill.exercise(RID, state, directory)
        update = next(i for i, x in enumerate(actions) if x.startswith('UPDATE '))
        delete = next(i for i, x in enumerate(actions) if x.startswith('DELETE '))
        self.assertLess(actions.index('dump'), actions.index('import'))
        self.assertLess(actions.index('import'), update)
        self.assertLess(update, delete)
        self.assertLess(delete, actions.index('audit-binlog'))
        self.assertLess(actions.index('audit-binlog'), actions.index('mysqlbinlog'))
        self.assertLess(actions.index('mysqlbinlog'), actions.index('replay'))
        self.assertEqual(actions[-1], 'phase:DATA_VERIFIED')
        self.assertEqual((state['backup_sha256'], state['binlog_sha256']), ('dump-sha', 'binlog-sha'))
        self.assertEqual((state['backup_start'][1], state['backup_after'][1], state['replay_stop'][1], state['fault_end'][1]), (123, 123, 234, 345))

    def test_import_grants_only_create_and_insert_in_isolated_schema(self):
        name = 'm04_import_' + '1' * 16
        principal = '`' + name + '`@`localhost`'
        with patch.object(drill.probe, 'query', return_value='GRANT USAGE ON *.* TO ' + principal + '\n'
                          + 'GRANT INSERT, CREATE ON `orderguard_restore_m04`.* TO ' + principal):
            drill.import_grants(RID, self.state, name)
        for grant in ('GRANT INSERT, CREATE, DROP ON `orderguard_restore_m04`.* TO ',
                      'GRANT INSERT, CREATE ON *.* TO '):
            with patch.object(drill.probe, 'query', return_value='GRANT USAGE ON *.* TO ' + principal + '\n' + grant + principal):
                with self.assertRaises(drill.ctl.SafetyError):
                    drill.import_grants(RID, self.state, name)

    def test_bad_backup_restore_prevents_injection(self):
        actions = []
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp, ExitStack() as stack:
            directory = Path(temp)
            dump = directory / 'dump'
            dump.write_bytes(b'dump')
            @contextmanager
            def dump_gate(fd, start, end):
                yield fd, types.SimpleNamespace(sha256='hash')
            stack.enter_context(patch.object(drill.probe, 'verify_observers'))
            stack.enter_context(patch.object(drill.business, 'verify_schema_contract'))
            stack.enter_context(patch.object(drill.probe, 'position', return_value=['pitr-bin.000001', 123]))
            stack.enter_context(patch.object(drill.probe, 'query', side_effect=lambda *a: actions.append(a[-1])))
            stack.enter_context(patch.object(drill, 'rows', side_effect=[[FIRST, SECOND], [FIRST]]))
            stack.enter_context(patch.object(drill, 'capture_dump', return_value=dump))
            stack.enter_context(patch.object(drill.backup_gate, 'audited_dump_stream', dump_gate))
            stack.enter_context(patch.object(drill, 'import_dump'))
            replay = stack.enter_context(patch.object(drill, 'restricted_replay'))
            stack.enter_context(patch.object(drill, 'phase'))
            stack.enter_context(patch.object(drill.ctl, 'save'))
            stack.enter_context(patch.object(drill.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True))
            with self.assertRaises(drill.ctl.SafetyError):
                drill.exercise(RID, self.state, directory)
            replay.assert_not_called()
            self.assertFalse(any(a.startswith(('UPDATE ', 'DELETE ')) for a in actions))

    def test_dump_and_import_commands_use_only_isolated_sockets_and_scoped_account(self):
        calls = []
        def run(args, **kwargs):
            calls.append((args, kwargs))
            if hasattr(kwargs.get('stdout'), 'write'):
                kwargs['stdout'].write(b'synthetic dump')
            return types.SimpleNamespace(returncode=0)
        @contextmanager
        def account(*args):
            yield 'm04_import_' + '1' * 16, 17
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp, ExitStack() as stack:
            directory = Path(temp)
            def paths(rid, label):
                return directory, directory, '/run/' + label + '/mysql.sock'
            stack.enter_context(patch.object(drill.ctl, 'require_same_boot'))
            stack.enter_context(patch.object(drill.ctl, 'verify'))
            stack.enter_context(patch.object(drill.ctl, 'paths', side_effect=paths))
            stack.enter_context(patch.object(drill.probe, 'probe_target_verified'))
            stack.enter_context(patch.object(drill.probe, 'query'))
            stack.enter_context(patch.object(drill, 'import_account', account))
            stack.enter_context(patch.object(drill.subprocess, 'run', side_effect=run))
            stack.enter_context(patch.object(drill.os, 'lseek'))
            drill.capture_dump(RID, self.state, directory)
            drill.import_dump(RID, self.state, directory, 18)
        dump, restore = calls
        self.assertIn('--socket=/run/source/mysql.sock', dump[0])
        self.assertEqual(dump[0][-2:], ['orderguard_restore_m04', 'orders'])
        self.assertIn('--source-data=2', dump[0])
        self.assertIn('--socket=/run/target/mysql.sock', restore[0])
        self.assertIn('--user=m04_import_' + '1' * 16, restore[0])
        self.assertIn('--database=orderguard_restore_m04', restore[0])
        self.assertEqual((restore[1]['stdin'], restore[1]['pass_fds']), (18, (17,)))

    def test_import_account_intent_is_removed_only_after_verified_absence(self):
        for absent, success in [('0', True), ('1', False)]:
            state = dict(self.state)
            saves, statements = [], []
            with tempfile.TemporaryFile(dir=Path(__file__).parent) as credential, ExitStack() as stack:
                stack.enter_context(patch.object(drill.os, 'MFD_CLOEXEC', 1, create=True))
                stack.enter_context(patch.object(drill.os, 'memfd_create', create=True, side_effect=lambda *a: os.dup(credential.fileno())))
                stack.enter_context(patch.object(drill.os, 'fchmod', create=True))
                stack.enter_context(patch.object(drill.accounts, 'account_exists', side_effect=['0', absent]))
                stack.enter_context(patch.object(drill.accounts, 'admin_statement', side_effect=lambda r, s, q: statements.append(q)))
                stack.enter_context(patch.object(drill, 'import_grants'))
                stack.enter_context(patch.object(drill.ctl, 'save', side_effect=lambda d, s: saves.append(copy.deepcopy(s))))
                if success:
                    with drill.import_account(RID, state, Path('.')):
                        self.assertIn('import_account', state)
                    self.assertNotIn('import_account', state)
                else:
                    with self.assertRaises(drill.ctl.SafetyError):
                        with drill.import_account(RID, state, Path('.')):
                            pass
                    self.assertIn('import_account', state)
            self.assertEqual(saves[0]['import_account']['status'], 'CREATE_ATTEMPTED')
            self.assertTrue(statements[-1].startswith('DROP USER IF EXISTS'))

    def test_replay_intent_survives_ambiguous_failure(self):
        state = self.state
        def fail(rid, current, directory, start, stop, end, data, replay):
            drill.accounts.account_exists(rid, current, 'm04_' + 'a' * 16)
            raise RuntimeError('absence check unavailable')
        with patch.object(drill.accounts, 'account_exists', return_value='0'), \
             patch.object(drill.probe, 'exercise', side_effect=fail), patch.object(drill.ctl, 'save'):
            with self.assertRaises(RuntimeError):
                drill.restricted_replay(RID, state, Path('.'), [None, 1], [None, 2], [None, 3], b'', 'x')
        self.assertEqual(state['candidate_replay_account']['name'], 'm04_' + 'a' * 16)

    def test_replay_intent_cleared_after_probe_confirms_absence(self):
        def passed(rid, current, directory, start, stop, end, data, replay):
            drill.accounts.account_exists(rid, current, 'm04_' + 'a' * 16)
            drill.accounts.account_exists(rid, current, 'm04_' + 'a' * 16)
        with patch.object(drill.accounts, 'account_exists', return_value='0'), \
             patch.object(drill.probe, 'exercise', side_effect=passed), patch.object(drill.ctl, 'save'):
            drill.restricted_replay(RID, self.state, Path('.'), [None, 1], [None, 2], [None, 3], b'', 'x')
        self.assertNotIn('candidate_replay_account', self.state)

    def test_main_failure_preserves_state_without_reset(self):
        saved = []
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary, ExitStack() as stack:
            stack.enter_context(patch.object(drill.ctl, 'BASE', Path(temporary)))
            stack.enter_context(patch.object(drill.ctl, 'setup'))
            stack.enter_context(patch.object(drill.ctl, 'locked', return_value=123456))
            stack.enter_context(patch.object(drill.ctl, 'boot_context', return_value=('boot', 1)))
            stack.enter_context(patch.object(drill.ctl, 'save', side_effect=lambda d, s: saved.append(copy.deepcopy(s))))
            def start(rid, directory, state):
                state['uuids'] = {'source': 'a', 'target': 'b'}
            stack.enter_context(patch.object(drill.ctl, 'start', side_effect=start))
            stack.enter_context(patch.object(drill.live_identity, 'bind', return_value={}))
            reset = stack.enter_context(patch.object(drill.live_identity, 'reset'))
            stack.enter_context(patch.object(drill, 'exercise', side_effect=RuntimeError('failed')))
            stack.enter_context(patch.object(drill.os, 'close'))
            stack.enter_context(patch.object(drill.signal, 'SIGALRM', 1, create=True))
            stack.enter_context(patch.object(drill.signal, 'ITIMER_REAL', 1, create=True))
            stack.enter_context(patch.object(drill.signal, 'getsignal', return_value=None))
            stack.enter_context(patch.object(drill.signal, 'signal'))
            stack.enter_context(patch.object(drill.signal, 'setitimer', create=True))
            stack.enter_context(patch.object(drill.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=4*1024**3)))
            stack.enter_context(patch('builtins.print'))
            with self.assertRaises(RuntimeError):
                drill.main()
            reset.assert_not_called()
        self.assertEqual(saved[-1]['candidate_phase'], 'NEEDS_INSPECTION')
        self.assertEqual(saved[-1]['candidate_error_type'], 'RuntimeError')

    def test_main_success_rechecks_both_instances_then_resets(self):
        calls, saved = [], []
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary, ExitStack() as stack:
            stack.enter_context(patch.object(drill.ctl, 'BASE', Path(temporary)))
            stack.enter_context(patch.object(drill.ctl, 'setup'))
            stack.enter_context(patch.object(drill.ctl, 'locked', return_value=123456))
            stack.enter_context(patch.object(drill.ctl, 'boot_context', return_value=('boot', 1)))
            stack.enter_context(patch.object(drill.ctl, 'save', side_effect=lambda d, s: saved.append(copy.deepcopy(s))))
            def start(rid, directory, state):
                state['uuids'] = {'source': 'a', 'target': 'b'}
            stack.enter_context(patch.object(drill.ctl, 'start', side_effect=start))
            stack.enter_context(patch.object(drill, 'exercise', side_effect=lambda *a: calls.append('exercise')))
            stack.enter_context(patch.object(drill.ctl, 'require_same_boot'))
            stack.enter_context(patch.object(drill.ctl, 'verify', side_effect=lambda r, label, *a: calls.append(label)))
            stack.enter_context(patch.object(drill.live_identity, 'bind', return_value={}))
            stack.enter_context(patch.object(drill.live_identity, 'reset', side_effect=lambda *a: calls.append('reset')))
            stack.enter_context(patch.object(drill.os, 'close'))
            stack.enter_context(patch.object(drill.signal, 'SIGALRM', 1, create=True))
            stack.enter_context(patch.object(drill.signal, 'ITIMER_REAL', 1, create=True))
            stack.enter_context(patch.object(drill.signal, 'getsignal', return_value=None))
            stack.enter_context(patch.object(drill.signal, 'signal'))
            stack.enter_context(patch.object(drill.signal, 'setitimer', create=True))
            stack.enter_context(patch.object(drill.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=4*1024**3)))
            stack.enter_context(patch('builtins.print'))
            drill.main()
        self.assertEqual(calls, ['exercise', 'reset'])
        self.assertEqual(saved[-1]['candidate_phase'], 'SYNTHETIC_RESET_COMPLETE')


if __name__ == '__main__':
    unittest.main()
