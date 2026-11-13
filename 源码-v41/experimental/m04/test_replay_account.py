import sys
import types
import unittest
from unittest.mock import patch
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))
import m04_replay_account as r

class ReplayAccountTests(unittest.TestCase):
    def setUp(self):
        self.guard = patch.object(r, 'ACCOUNT_SAFETY_READY', True).start()
        self.save = patch.object(r.ctl, 'save').start()
        self.addCleanup(patch.stopall)
        self.state = {'primary_uuid': 'primary', 'uuids': {'target': 'target'}}
        self.os_patches = [patch.object(r.os, 'memfd_create', return_value=7, create=True),
                           patch.object(r.os, 'MFD_CLOEXEC', 1, create=True),
                           patch.object(r.os, 'fchmod', create=True), patch.object(r.os, 'write'), patch.object(r.os, 'lseek'), patch.object(r.os, 'close')]
        for p in self.os_patches:
            p.start()
            self.addCleanup(p.stop)
        r.os.write.side_effect = lambda fd, data: len(data)

    @patch.object(r, 'account_exists', return_value='0')
    @patch.object(r, 'admin_statement')
    def test_partial_credential_write_is_completed_before_account_creation(self, admin, exists):
        chunks = []
        def partial_write(fd, data):
            count = min(7, len(data))
            chunks.append(data[:count])
            return count
        r.os.write.side_effect = partial_write
        with r.replay_account('0123456789abcdef', '.', self.state):
            credential = b''.join(chunks)
            self.assertTrue(credential.startswith(b'[client]\npassword='))
            self.assertEqual(len(credential.split(b'password=')[1].strip()), 64)
            self.assertGreater(len(chunks), 1)

    @patch.object(r, 'account_exists', return_value='0')
    @patch.object(r, 'admin_statement')
    def test_zero_credential_write_fails_before_creation(self, admin, exists):
        r.os.write.side_effect = None
        r.os.write.return_value = 0
        with self.assertRaisesRegex(r.ctl.SafetyError, 'cannot write replay credentials'):
            with r.replay_account('0123456789abcdef', '.', self.state):
                self.fail('must not yield')
        self.assertEqual(len(admin.call_args_list), 1)
        self.assertTrue(admin.call_args.args[2].startswith('DROP USER IF EXISTS'))

    @patch.object(r, 'account_exists', return_value='0')
    @patch.object(r, 'admin_statement')
    def test_only_update_and_applier_and_cleanup(self, admin, exists):
        with r.replay_account('0123456789abcdef', '.', self.state) as account:
            self.assertTrue(account.name.startswith('m04_'))
        statements = [c.args[2] for c in admin.call_args_list]
        self.assertEqual(len(statements), 4)
        self.assertIn('GRANT REPLICATION_APPLIER ON *.*', statements[1])
        self.assertIn('GRANT UPDATE ON `orderguard_restore_m04`.`orders`', statements[2])
        self.assertNotIn('DELETE', ' '.join(statements))
        self.assertTrue(statements[3].startswith('DROP USER IF EXISTS'))
        self.assertNotIn('password=', repr(statements[1:]))

    @patch.object(r, 'account_exists', return_value='0')
    @patch.object(r, 'admin_statement')
    def test_cleanup_on_grant_failure(self, admin, exists):
        admin.side_effect = [None, RuntimeError('grant failed'), None]
        with self.assertRaisesRegex(RuntimeError, 'grant failed'):
            with r.replay_account('0123456789abcdef', '.', self.state):
                self.fail('must not yield')
        self.assertTrue(admin.call_args_list[-1].args[2].startswith('DROP USER IF EXISTS'))
        r.os.close.assert_called_once_with(7)

    @patch.object(r, 'account_exists', return_value='0')
    @patch.object(r, 'admin_statement')
    def test_cleanup_failure_is_visible(self, admin, exists):
        admin.side_effect = [None, None, None, RuntimeError('failed')]
        with self.assertRaises(r.CleanupError):
            with r.replay_account('0123456789abcdef', '.', self.state):
                pass

    @patch.object(r, 'account_exists', return_value='1')
    @patch.object(r, 'admin_statement')
    def test_existing_account_never_modified(self, admin, exists):
        with self.assertRaises(r.ctl.SafetyError):
            with r.replay_account('0123456789abcdef', '.', self.state):
                pass
        admin.assert_not_called()

    @patch.object(r.ctl, 'sql', return_value='1\t0\t0')
    @patch.object(r.ctl, 'verify')
    def test_query_log_enabled_refuses_credentials(self, verify, sql):
        with self.assertRaises(r.ctl.SafetyError):
            r.target_verified('0123456789abcdef', self.state)

    @patch.object(r, 'admin_statement')
    def test_crash_record_cleanup(self, admin):
        self.state['replay_account'] = {'name': 'm04_0123456789abcdef', 'status': 'CREATE_ATTEMPTED'}
        r.cleanup_recorded_account('0123456789abcdef', '.', self.state)
        self.assertNotIn('replay_account', self.state)
        self.assertTrue(admin.call_args.args[2].startswith('DROP USER IF EXISTS'))
        self.save.assert_called_once()

    @patch.object(r, 'admin_statement', side_effect=RuntimeError('offline'))
    def test_failed_crash_cleanup_retains_record(self, admin):
        self.state['replay_account'] = {'name': 'm04_0123456789abcdef', 'status': 'CREATE_ATTEMPTED'}
        with self.assertRaises(RuntimeError):
            r.cleanup_recorded_account('0123456789abcdef', '.', self.state)
        self.assertIn('replay_account', self.state)

    @patch.object(r, 'target_verified')
    @patch.object(r.subprocess, 'run')
    def test_apply_refuses_unsealed_stream(self, run, target):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for name, value in [('F_SEAL_WRITE', 8), ('F_SEAL_GROW', 4), ('F_SEAL_SHRINK', 2),
                                ('F_SEAL_SEAL', 1), ('F_GET_SEALS', 1034)]:
                stack.enter_context(patch.object(r.fcntl, name, value, create=True))
            stack.enter_context(patch.object(r.fcntl, 'fcntl', return_value=0, create=True))
            account = r.ReplayAccount('0123456789abcdef', self.state, 'm04_0123456789abcdef', 7)
            with self.assertRaises(r.ctl.SafetyError):
                account.apply(8)
            run.assert_not_called()

    @patch.object(r, 'account_exists', return_value='0')
    @patch.object(r, 'admin_statement')
    def test_crash_before_account_creation_preserves_durable_intent(self, admin, exists):
        r.os.memfd_create.side_effect = OSError('allocation failed')
        with self.assertRaises(OSError):
            with r.replay_account('0123456789abcdef', '.', self.state):
                pass
        self.assertEqual(self.state['replay_account']['status'], 'CREATE_ATTEMPTED')
        self.save.assert_called_once()
        admin.assert_not_called()

    @patch.object(r, 'admin_statement')
    def test_bad_crash_record_never_drops_account(self, admin):
        for record in ({'name': 'root', 'status': 'CREATE_ATTEMPTED'},
                       {'name': 'm04_0123456789abcdef', 'status': 'UNKNOWN'},
                       {'name': "m04_0123456789abcd'", 'status': 'CREATE_ATTEMPTED'}):
            self.state['replay_account'] = record
            with self.assertRaises(r.ctl.SafetyError):
                r.cleanup_recorded_account('0123456789abcdef', '.', self.state)
        admin.assert_not_called()
        self.save.assert_not_called()

    @patch.object(r, 'account_exists', return_value='0')
    @patch.object(r, 'admin_statement')
    def test_creation_intent_persisted_before_first_admin_call(self, admin, exists):
        import copy
        persisted = []
        self.save.side_effect = lambda directory, state: persisted.append(copy.deepcopy(state))
        def inspect(rid, state, sql):
            if sql.startswith('CREATE USER'):
                self.assertEqual(persisted[-1]['replay_account']['status'], 'CREATE_ATTEMPTED')
                self.assertNotIn('password', repr(persisted[-1]).lower())
        admin.side_effect = inspect
        with r.replay_account('0123456789abcdef', '.', self.state):
            pass
        self.assertNotIn('replay_account', persisted[-1])

    @patch.object(r, 'ACCOUNT_SAFETY_READY', False)
    @patch.object(r, 'account_exists')
    def test_account_provisioning_guard_refuses_before_identity_or_secret(self, exists):
        with self.assertRaisesRegex(r.ctl.SafetyError, 'disabled'):
            with r.replay_account('0123456789abcdef', '.', self.state):
                pass
        exists.assert_not_called()
        self.save.assert_not_called()

    @patch.object(r.ctl, 'verify')
    @patch.object(r.ctl, 'sql')
    def test_logging_and_plugins_are_fail_closed(self, sql, verify):
        for first in ('1\t0\t0', '0\t1\t0', '0\t0\t1'):
            sql.side_effect = [first]
            with self.assertRaises(r.ctl.SafetyError):
                r.target_verified('0123456789abcdef', self.state)
        for answers in (['0\t0\t0', '1'], ['0\t0\t0', '0', '1']):
            sql.side_effect = answers
            with self.assertRaises(r.ctl.SafetyError):
                r.target_verified('0123456789abcdef', self.state)
        sql.side_effect = ['0\t0\t0', '0', '0']
        r.target_verified('0123456789abcdef', self.state)

    @patch.object(r, 'account_exists', return_value='0')
    @patch.object(r, 'admin_statement')
    def test_server_exit_on_grant_and_cleanup_leaves_record(self, admin, exists):
        admin.side_effect = [None, RuntimeError('target exited'), RuntimeError('target exited')]
        with self.assertRaises(r.CleanupError):
            with r.replay_account('0123456789abcdef', '.', self.state):
                self.fail('must not yield')
        self.assertEqual(self.state['replay_account']['status'], 'CREATE_ATTEMPTED')
        self.assertEqual(self.save.call_count, 1)

    @patch.object(r, 'target_verified')
    @patch.object(r.subprocess, 'run')
    def test_admin_credential_only_in_stdin_and_suppressed_output(self, run, verified):
        run.return_value = type('Result', (), {'returncode': 0})()
        statement = "CREATE USER 'sample'@'localhost' IDENTIFIED BY 'test-marker-only';"
        r.admin_statement('0123456789abcdef', self.state, statement)
        call = run.call_args
        self.assertNotIn('test-marker-only', repr(call.args))
        self.assertEqual(call.kwargs['input'], statement.encode('ascii'))
        self.assertIs(call.kwargs['stdout'], r.subprocess.DEVNULL)
        self.assertIs(call.kwargs['stderr'], r.subprocess.DEVNULL)

    @patch.object(r, 'ACCOUNT_SAFETY_READY', False)
    @patch.object(r, 'target_verified')
    def test_apply_guard_refuses_before_target_access(self, verified):
        account = r.ReplayAccount('0123456789abcdef', self.state, 'm04_0123456789abcdef', 7)
        with self.assertRaises(r.ctl.SafetyError):
            account.apply(8)
        verified.assert_not_called()

if __name__ == '__main__':
    unittest.main()
