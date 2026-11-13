import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

# The controller runs on Linux; stub OS-specific imports for local Windows tests.
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))
spec = importlib.util.spec_from_file_location('m04_controller', Path(__file__).with_name('m04_controller.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RID = '0123456789abcdef'
PRIMARY = '11111111-1111-1111-1111-111111111111'
OTHER = '22222222-2222-2222-2222-222222222222'

class ControllerTests(unittest.TestCase):
    def test_identity_and_commands_are_derived(self):
        with self.assertRaises(m.SafetyError):
            m.paths('../../etc', 'source')
        with self.assertRaises(m.SafetyError):
            m.paths(RID, 'primary')
        args = m.command(RID, 'source')
        self.assertIn('--skip-networking', args)
        self.assertIn('--no-defaults', args)
        self.assertTrue(any(x.startswith('--log-bin=') for x in args))
        self.assertIn('--skip-log-bin', m.command(RID, 'target'))

    @patch.object(m, 'owned_process')
    @patch.object(m, 'properties', return_value={'ActiveState': 'active'})
    @patch.object(m, 'sql')
    def test_verify_rejects_primary_uuid_and_network(self, sql, properties, owned):
        root, data, sock = m.paths(RID, 'source')
        def row(uuid, networking='1'):
            return f'{data}\t{sock}\t{networking}\t1\t{uuid}\tROW'
        sql.return_value = row(PRIMARY)
        with self.assertRaises(m.SafetyError):
            m.verify(RID, 'source', PRIMARY)
        sql.return_value = row(OTHER, '0')
        with self.assertRaises(m.SafetyError):
            m.verify(RID, 'source', PRIMARY)
        sql.return_value = row(OTHER)
        self.assertEqual(m.verify(RID, 'source', PRIMARY), OTHER)
        with self.assertRaises(m.SafetyError):
            m.verify(RID, 'source', PRIMARY, PRIMARY)

    @patch.object(m, 'run')
    @patch.object(m, 'owned_process', side_effect=m.SafetyError('identity mismatch'))
    @patch.object(m, 'properties', return_value={'ActiveState': 'active'})
    def test_refuses_stop_when_identity_mismatches(self, properties, owned, run):
        with self.assertRaises(m.SafetyError):
            m.stop_one(RID, 'source')
        run.assert_not_called()

    @patch.object(m, 'save')
    @patch.object(m, 'stop_one')
    def test_reset_attempts_both_and_records_failure(self, stop, save):
        stop.side_effect = [m.SafetyError('bad target'), None]
        state = {'phase': 'READY', 'attempted': [m.unit(RID, 'target'), m.unit(RID, 'source')]}
        with self.assertRaises(m.SafetyError):
            m.reset(RID, Path('.'), state)
        self.assertEqual([x.args[1] for x in stop.call_args_list], ['target', 'source'])
        self.assertEqual(state['phase'], 'FAILED')
        self.assertEqual(save.call_count, 2)

    @patch.object(m, 'save')
    @patch.object(m, 'stop_one')
    def test_reset_success_is_stopped(self, stop, save):
        state = {'phase': 'READY', 'attempted': [m.unit(RID, 'target'), m.unit(RID, 'source')]}
        m.reset(RID, Path('.'), state)
        self.assertEqual(state['phase'], 'STOPPED')
        self.assertEqual(stop.call_count, 2)

    @patch.object(m, 'properties', return_value={'LoadState': 'not-found', 'ActiveState': 'inactive'})
    @patch.object(m, 'run')
    def test_not_found_still_checks_socket(self, run, properties):
        with patch.object(m, 'paths', return_value=(None, None, Path(__file__))):
            with self.assertRaisesRegex(m.SafetyError, 'socket remains'):
                m.stop_one(RID, 'source')
        run.assert_not_called()

    @patch.object(m, 'properties', return_value={'LoadState': 'not-found', 'ActiveState': 'inactive'})
    @patch.object(m, 'run')
    def test_absent_init_is_safe(self, run, properties):
        m.stop_one(RID, 'source', True)
        run.assert_not_called()

    @patch.object(m, 'save')
    @patch.object(m, 'properties', return_value={'LoadState': 'loaded', 'ActiveState': 'active'})
    @patch.object(m, 'run')
    def test_preexisting_unit_not_claimed_or_started(self, run, properties, save):
        state = {'attempted': []}
        with self.assertRaisesRegex(m.SafetyError, 'already exists'):
            m.launch(RID, 'source', True, Path('.'), state)
        self.assertEqual(state['attempted'], [])
        run.assert_not_called()
        save.assert_not_called()

    @patch.object(m, 'save')
    @patch.object(m, 'properties', return_value={'LoadState': 'not-found', 'ActiveState': 'inactive'})
    @patch.object(m, 'run', side_effect=__import__('subprocess').TimeoutExpired('systemd-run', 150))
    def test_timeout_records_init_for_recovery(self, run, properties, save):
        state = {'attempted': []}
        with self.assertRaises(__import__('subprocess').TimeoutExpired):
            m.launch(RID, 'source', True, Path('.'), state)
        self.assertEqual(state['attempted'], [m.init_unit(RID, 'source')])
        self.assertEqual(save.call_count, 1)

    @patch.object(m, 'run')
    @patch.object(m, 'owned_process')
    @patch.object(m, 'properties', side_effect=[{'ActiveState': 'active'}, {'ActiveState': 'inactive'}])
    def test_active_init_verified_then_stopped(self, properties, owned, run):
        m.stop_one(RID, 'source', True)
        owned.assert_called_once_with(RID, 'source', {'ActiveState': 'active'}, True)
        run.assert_called_once_with(['/usr/bin/systemctl', 'stop', m.init_unit(RID, 'source')])

    @patch.object(m, 'save')
    @patch.object(m, 'stop_one')
    def test_wrong_run_unit_cannot_be_stopped(self, stop, save):
        state = {'phase': 'READY', 'attempted': [m.init_unit('fedcba9876543210', 'source')]}
        with self.assertRaisesRegex(m.SafetyError, 'invalid attempted units'):
            m.reset(RID, Path('.'), state)
        stop.assert_not_called()

    @patch.object(m, 'save')
    @patch.object(m, 'stop_one')
    def test_reset_stops_both_init_and_server(self, stop, save):
        state = {'attempted': [m.init_unit(RID, 'source'), m.unit(RID, 'source')]}
        m.reset(RID, Path('.'), state)
        self.assertEqual([c.args[2] for c in stop.call_args_list], [False, True])

    @patch.object(m, 'save')
    @patch.object(m, 'stop_one')
    def test_reset_attempts_account_cleanup_before_stopping(self, stop, save):
        import m04_replay_account as account
        state = {'attempted': [m.unit(RID, 'target')],
                 'replay_account': {'name': 'm04_0123456789abcdef', 'status': 'CREATE_ATTEMPTED'}}
        with patch.object(account, 'cleanup_recorded_account') as cleanup:
            m.reset(RID, Path('.'), state)
        cleanup.assert_called_once_with(RID, Path('.'), state)
        stop.assert_called_once()

    @patch.object(m, 'save')
    @patch.object(m, 'stop_one')
    def test_reset_still_stops_if_account_cleanup_fails(self, stop, save):
        import m04_replay_account as account
        state = {'attempted': [m.unit(RID, 'target')], 'replay_account': {'name': 'x'}}
        with patch.object(account, 'cleanup_recorded_account', side_effect=RuntimeError('cannot verify')):
            with self.assertRaises(m.SafetyError):
                m.reset(RID, Path('.'), state)
        stop.assert_called_once()
        self.assertEqual(state['phase'], 'FAILED')
        self.assertIn('replay_account', state)

    @patch.object(m, 'boot_context')
    def test_boot_identity_and_boot_clock(self, context):
        context.return_value = ('11111111-1111-1111-1111-111111111111', 150.0)
        state = {'boot_id': context.return_value[0], 'deadline_boottime': 200.0}
        self.assertEqual(m.require_same_boot(state), 150.0)
        state['boot_id'] = '22222222-2222-2222-2222-222222222222'
        with self.assertRaisesRegex(m.SafetyError, 'different boot'):
            m.require_same_boot(state)
        with self.assertRaises(m.SafetyError):
            m.require_same_boot({'deadline': 9999999999})

if __name__ == '__main__':
    unittest.main()

