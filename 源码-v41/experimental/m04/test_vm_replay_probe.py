import sys
import types
import unittest
import contextlib
import copy
import tempfile
from pathlib import Path
from unittest.mock import patch
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))
import vm_replay_probe as probe

class ProbeTests(unittest.TestCase):
    def test_exercise_uses_account_and_apply_and_restores_overrides(self):
        rid = '0123456789abcdef'
        state = {'run_id': rid, 'business_phase': 'TEST_ONLY'}
        saved, statements, writes = [], [], []
        fake_os = types.SimpleNamespace(memfd_create=lambda *a, **k: 71, MFD_CLOEXEC=1,
                                       fchmod=lambda *a: None, lseek=lambda *a: 0,
                                       close=lambda *a: None,
                                       write=lambda fd, data: writes.append(data) or len(data), SEEK_SET=0)
        fake_fcntl = types.SimpleNamespace(F_SEAL_WRITE=8, F_SEAL_GROW=4, F_SEAL_SHRINK=2,
                                           F_SEAL_SEAL=1, F_GET_SEALS=1034, fcntl=lambda *a: 15)
        @contextlib.contextmanager
        def stream(*args):
            yield 72
        original_verify = probe.accounts.target_verified
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            replay = Path(tmp) / 'replay.sql'
            replay.write_bytes(b'replay')
            stack.enter_context(patch.object(probe, 'probe_target_verified'))
            stack.enter_context(patch.object(probe, 'verify_exact_grants'))
            stack.enter_context(patch.object(probe, 'query', side_effect=['101', '1', '1']))
            denied = stack.enter_context(patch.object(probe, 'client', return_value=(1, b'ERROR 1142 (42000)')))
            stack.enter_context(patch.object(probe.sealed_replay, 'audited_replay_stream', stream))
            stack.enter_context(patch.object(probe.accounts, 'os', fake_os))
            stack.enter_context(patch.object(probe.accounts, 'fcntl', fake_fcntl))
            stack.enter_context(patch.object(probe.accounts, 'account_exists', return_value='0'))
            stack.enter_context(patch.object(probe.accounts, 'admin_statement', side_effect=lambda r, s, sql: statements.append(sql)))
            stack.enter_context(patch.object(probe.ctl, 'save', side_effect=lambda d, s: saved.append(copy.deepcopy(s))))
            stack.enter_context(patch.object(probe.ctl, 'paths', return_value=(None, None, '/tmp/isolated.sock')))
            run = stack.enter_context(patch.object(probe.accounts.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0)))
            marker = probe.exercise(rid, state, tmp, ['pitr-bin.000001', 4], ['pitr-bin.000001', 5],
                                    ['pitr-bin.000001', 6], b'binlog', replay)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.kwargs['stdin'], 72)
            self.assertEqual(denied.call_count, 2)
            self.assertEqual(saved[0]['replay_account']['status'], 'CREATE_ATTEMPTED')
            self.assertNotIn('replay_account', saved[-1])
            self.assertTrue(statements[-1].startswith('DROP USER IF EXISTS'))
            self.assertIn(marker.encode('ascii'), b''.join(writes))
            self.assertEqual(len(marker), 64)
            self.assertFalse(probe.accounts.ACCOUNT_SAFETY_READY)
            self.assertIs(probe.accounts.target_verified, original_verify)

    def test_exercise_rejects_non_test_state_before_overrides(self):
        original_verify = probe.accounts.target_verified
        with self.assertRaises(probe.ctl.SafetyError):
            probe.exercise('0123456789abcdef', {}, '.', [None, 4], [None, 5], [None, 6], b'', 'absent')
        self.assertFalse(probe.accounts.ACCOUNT_SAFETY_READY)
        self.assertIs(probe.accounts.target_verified, original_verify)

    def test_exercise_failure_drops_account_and_restores_overrides(self):
        rid = '0123456789abcdef'
        state = {'run_id': rid, 'business_phase': 'TEST_ONLY'}
        saved, statements = [], []
        fake_os = types.SimpleNamespace(memfd_create=lambda *a, **k: 71, MFD_CLOEXEC=1,
                                       fchmod=lambda *a: None, lseek=lambda *a: 0,
                                       close=lambda *a: None, write=lambda fd, data: len(data), SEEK_SET=0)
        @contextlib.contextmanager
        def stream(*args):
            yield 72
        original_verify = probe.accounts.target_verified
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            replay = Path(tmp) / 'replay.sql'
            replay.write_bytes(b'replay')
            stack.enter_context(patch.object(probe, 'probe_target_verified'))
            stack.enter_context(patch.object(probe, 'verify_exact_grants', side_effect=RuntimeError('grant mismatch')))
            stack.enter_context(patch.object(probe.sealed_replay, 'audited_replay_stream', stream))
            stack.enter_context(patch.object(probe.accounts, 'os', fake_os))
            stack.enter_context(patch.object(probe.accounts, 'account_exists', return_value='0'))
            stack.enter_context(patch.object(probe.accounts, 'admin_statement', side_effect=lambda r, s, sql: statements.append(sql)))
            stack.enter_context(patch.object(probe.ctl, 'save', side_effect=lambda d, s: saved.append(copy.deepcopy(s))))
            with self.assertRaisesRegex(RuntimeError, 'grant mismatch'):
                probe.exercise(rid, state, tmp, ['pitr-bin.000001', 4], ['pitr-bin.000001', 5],
                               ['pitr-bin.000001', 6], b'binlog', replay)
        self.assertTrue(statements[-1].startswith('DROP USER IF EXISTS'))
        self.assertEqual(saved[0]['replay_account']['status'], 'CREATE_ATTEMPTED')
        self.assertNotIn('replay_account', saved[-1])
        self.assertFalse(probe.accounts.ACCOUNT_SAFETY_READY)
        self.assertIs(probe.accounts.target_verified, original_verify)

    def test_permission_denial_requires_actual_table_denial(self):
        probe.deny((1, b'ERROR 1142 (42000): UPDATE command denied'))
        for result in ((0, b''), (1, b'ERROR 1045 (28000): Access denied'), (1, b'connection failed')):
            with self.assertRaises(probe.ctl.SafetyError):
                probe.deny(result)

    @patch.object(probe, 'query')
    def test_position_disallows_unexpected_log(self, query):
        query.return_value = 'pitr-bin.000002\t123'
        self.assertEqual(probe.position('0123456789abcdef', {}), ['pitr-bin.000002', 123])
        query.return_value = '../../primary-bin.000001\t123'
        with self.assertRaises(probe.ctl.SafetyError):
            probe.position('0123456789abcdef', {})

    @patch.object(probe.accounts, 'target_verified')
    @patch.object(probe.subprocess, 'run')
    @patch.object(probe.os, 'lseek')
    def test_test_credential_is_a_memfd_option_not_argument(self, seek, run, verify):
        run.return_value = type('Result', (), {'returncode': 1, 'stderr': b'ERROR 1142 (42000)'})()
        probe.client('0123456789abcdef', {}, 'm04_0123456789abcdef', 7, statement='DELETE FROM x;')
        args = run.call_args.args[0]
        self.assertIn('--defaults-extra-file=/proc/self/fd/7', args)
        self.assertNotIn('M04_NON_SECRET_TEST_MARKER', repr(args))
        self.assertEqual(run.call_args.kwargs['pass_fds'], (7,))

    def test_fixture_values_are_synthetic_and_fixed(self):
        self.assertIn('m04-synthetic-a', probe.TABLE_SQL)
        self.assertEqual(probe.DELETED_ROW[0], str(probe.ID_DELETE))
        self.assertNotIn('/etc/opsdrill/mysql-admin.cnf', probe.TABLE_SQL)

    def test_scan_detects_marker_without_returning_log_content(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'server.log').write_text('ordinary log M04_NON_SECRET_TEST_MARKER_123')
            (root / 'init.log').write_text('ordinary log')
            with patch.object(probe.ctl, 'paths', return_value=(root, None, None)):
                result = probe.scan_instance_logs('0123456789abcdef', 'M04_NON_SECRET_TEST_MARKER_123')
            self.assertEqual(result, {'server.log': True, 'init.log': False})
            self.assertNotIn('ordinary log', repr(result))

    @patch.object(probe.ctl, 'verify')
    def test_binlog_name_rejected_before_file_access(self, verify):
        with self.assertRaises(probe.ctl.SafetyError):
            probe.load_binlog('0123456789abcdef', {'uuids': {'source': 'x'}}, '../../mysql-bin.000001')
        verify.assert_not_called()

if __name__ == '__main__':
    unittest.main()
