import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, call
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))
import m04_controller as ctl
import m04_business as b
RID = '0123456789abcdef'

class BusinessTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(b, 'BUSINESS_ENABLED', True)
        patcher.start()
        self.addCleanup(patcher.stop)
        boot = patch.object(ctl, 'require_same_boot', side_effect=lambda state: b.time.time())
        boot.start()
        self.addCleanup(boot.stop)

    def state(self, phase):
        return {'phase': 'READY', 'business_phase': phase, 'deadline_boottime': 5000,
                'primary_uuid': 'primary', 'uuids': {'source': 'source'}}

    @patch.object(b.time, 'time', return_value=4990)
    @patch.object(ctl, 'verify')
    def test_refuses_operation_near_deadline(self, verify, clock):
        with self.assertRaises(ctl.SafetyError):
            b.ready(RID, self.state('NEW'), 30)
        verify.assert_not_called()

    @patch.object(ctl, 'verify')
    @patch.object(b.time, 'time', return_value=1)
    @patch.object(ctl, 'sql', return_value='ok')
    def test_query_verifies_source_identity_first(self, sql, clock, verify):
        s = self.state('IMPORTED')
        self.assertEqual(b.query(RID, s, 'SELECT 1'), 'ok')
        verify.assert_called_once_with(RID, 'source', 'primary', 'source')
        sql.assert_called_once_with(RID, 'source', 'SELECT 1')

    @patch.object(b, 'ready')
    def test_refuses_retry_after_ambiguous_import(self, ready):
        with self.assertRaises(ctl.SafetyError):
            b.import_backup(RID, Path('.'), self.state('IMPORTING'))
        ready.assert_not_called()

    @patch.object(b, 'ready')
    def test_refuses_injection_without_completed_import(self, ready):
        for stage in ('NEW', 'IMPORTING', 'INJECT_FAILED', 'INJECTED'):
            with self.assertRaises(ctl.SafetyError):
                b.inject(RID, Path('.'), self.state(stage))
        ready.assert_not_called()

    @patch.object(b, 'query', side_effect=['pitr-bin.000002\t100'])
    def test_position_parse(self, query):
        self.assertEqual(b.position(RID, self.state('IMPORTED')), ['pitr-bin.000002', 100])

    @patch.object(b, 'query', side_effect=['../../mysql-bin.000001\t100'])
    def test_position_rejects_wrong_binlog(self, query):
        with self.assertRaises(ctl.SafetyError):
            b.position(RID, self.state('IMPORTED'))

    @patch.object(b, 'ready')
    def test_restore_and_drill_check_refuse_incomplete_stages(self, ready):
        for stage in ('NEW', 'IMPORTING', 'RESTORE_FAILED', 'INJECT_FAILED'):
            with self.assertRaises(ctl.SafetyError):
                b.restore(RID, Path('.'), self.state(stage))
            with self.assertRaises(ctl.SafetyError):
                b.check_drill(RID, Path('.'), self.state(stage))
        ready.assert_not_called()

    @patch.object(b, 'ready')
    def test_restore_rejects_bad_log_identity_before_writes(self, ready):
        s = self.state('INJECTED')
        s['business'] = {'start': ['../../mysql-bin.000001', 4], 'stop': ['../../mysql-bin.000001', 50],
                         'end': ['../../mysql-bin.000001', 100]}
        with self.assertRaises(ctl.SafetyError):
            b.restore(RID, Path('.'), s)

    @patch.object(ctl, 'sql', return_value='10\trow')
    @patch.object(b, 'ready')
    def test_deleted_row_hash_requires_exactly_one_row(self, ready, sql):
        s = self.state('RESTORED')
        self.assertEqual(b.deleted_hash(RID, s, 'target', 10), __import__('hashlib').sha256(b'10\trow').hexdigest())
        sql.return_value = 'row1\nrow2'
        with self.assertRaises(ctl.SafetyError):
            b.deleted_hash(RID, s, 'target', 10)

    @patch.object(b, 'BUSINESS_ENABLED', False)
    @patch.object(b, 'ready')
    def test_all_business_entrypoints_fail_closed(self, ready):
        for operation in (b.import_backup, b.inject, b.restore, b.check_drill, b.finalize):
            with self.assertRaisesRegex(ctl.SafetyError, 'disabled pending safety review'):
                operation(RID, Path('.'), self.state('RESTORED'))
        ready.assert_not_called()

    @patch.object(b, 'BUSINESS_ENABLED', True)
    @patch.object(b.time, 'time', return_value=1)
    @patch.object(ctl, 'save')
    def test_stage_failure_persists_terminal_status(self, save, clock):
        import signal
        from unittest.mock import patch
        with patch.object(signal, 'SIGALRM', 14, create=True), patch.object(signal, 'ITIMER_REAL', 0, create=True), \
             patch.object(signal, 'setitimer', create=True) as timer, \
             patch.object(signal, 'getsignal', return_value=0), patch.object(signal, 'signal'):
            state = self.state('IMPORTED')
            with self.assertRaisesRegex(RuntimeError, 'oops'):
                b.run_bounded_stage('inject', lambda *args: (_ for _ in ()).throw(RuntimeError('oops')),
                                    RID, Path('.'), state)
            self.assertEqual(state['business_phase'], 'INJECT_FAILED')
            save.assert_called_once()
            self.assertEqual(timer.call_args_list[-1].args, (0, 0))

    @patch.object(b, 'BUSINESS_ENABLED', False)
    @patch.object(ctl, 'save')
    def test_disabled_stage_does_not_mark_failure(self, save):
        state = self.state('IMPORTED')
        with self.assertRaises(ctl.SafetyError):
            b.run_bounded_stage('inject', lambda *args: None, RID, Path('.'), state)
        self.assertEqual(state['business_phase'], 'IMPORTED')
        save.assert_not_called()

    @patch.object(b, 'BUSINESS_ENABLED', True)
    @patch.object(b, 'phase')
    @patch.object(b, 'primary_snapshot')
    @patch.object(ctl, 'run', return_value='active')
    @patch.object(ctl, 'properties', return_value={'LoadState': 'not-found', 'ActiveState': 'inactive'})
    @patch.object(b.os.path, 'lexists', return_value=False)
    def test_final_requires_stopped_instances_and_matching_primary(self, exists, props, run, snapshot, phase):
        state = self.state('DATA_VERIFIED')
        state['phase'] = 'STOPPED'
        state['primary_baseline'] = {'uuid': 'primary', 'orders_sha256': 'x', 'bytes': 1}
        snapshot.return_value = state['primary_baseline'].copy()
        b.finalize(RID, Path('.'), state)
        self.assertEqual([c.args[2] for c in phase.call_args_list], ['FINALIZING', 'FINAL_VERIFIED'])
        snapshot.return_value = {'uuid': 'primary', 'orders_sha256': 'changed', 'bytes': 1}
        phase.reset_mock()
        with self.assertRaises(ctl.SafetyError):
            b.finalize(RID, Path('.'), state)
        self.assertEqual([c.args[2] for c in phase.call_args_list], ['FINALIZING'])

    @patch.object(b, 'BUSINESS_ENABLED', True)
    @patch.object(b, 'primary_snapshot')
    def test_final_rejects_running_or_unclean_state(self, snapshot):
        state = self.state('DATA_VERIFIED')
        with self.assertRaises(ctl.SafetyError):
            b.finalize(RID, Path('.'), state)
        state['phase'] = 'STOPPED'
        state['replay_account'] = {'name': 'm04_0123456789abcdef'}
        with self.assertRaises(ctl.SafetyError):
            b.finalize(RID, Path('.'), state)
        snapshot.assert_not_called()

if __name__ == '__main__':
    unittest.main()
