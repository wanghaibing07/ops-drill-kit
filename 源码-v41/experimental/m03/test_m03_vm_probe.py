import copy
import subprocess
import types
import unittest
from unittest.mock import Mock, patch

import m03_vm_probe as p


class ProbeTests(unittest.TestCase):
    def test_limit_and_error_are_fail_closed(self):
        for value in ('0', '13', '-1', '1\n', '١', 'abc'):
            with self.assertRaises(RuntimeError):
                p.bounded_limit(value)
        self.assertEqual(p.bounded_limit('8'), 8)
        self.assertTrue(p.is_1040(subprocess.CompletedProcess([], 1, b'', b'ERROR 1040 (08004): Too many connections')))
        self.assertFalse(p.is_1040(subprocess.CompletedProcess([], 1, b'', b'ERROR 1045 (28000): Access denied')))
        self.assertFalse(p.is_1040(subprocess.CompletedProcess([], 0, b'', b'ERROR 1040 (08004)')))

    def test_identity_checked_before_use(self):
        ctl = Mock()
        state = {'run_id': '0123456789abcdef', 'business_phase': 'M03_TEST_ONLY', 'phase': 'READY',
                 'primary_uuid': p.ZERO_UUID, 'uuids': {'source': 'a', 'target': 'b'}}
        p.target(ctl, state['run_id'], state)
        ctl.verify.assert_called_once_with(state['run_id'], 'target', p.ZERO_UUID, 'b')
        state['business_phase'] = 'NEW'
        with self.assertRaises(RuntimeError):
            p.target(ctl, state['run_id'], state)
        self.assertEqual(ctl.verify.call_count, 1)

    def test_real_flow_records_1040_recovery_and_account_cleanup(self):
        self.run_flow(fail_refusal=False)

    def test_wrong_error_fails_and_still_stops_holders(self):
        self.run_flow(fail_refusal=True)

    def run_flow(self, fail_refusal):
        rid = '0123456789abcdef'
        name = 'm03_' + rid
        state = {}
        records = []
        ctl = Mock()
        ctl.ENV = {}
        ctl.paths.return_value = (None, None, '/isolated/mysql.sock')
        ctl.save.side_effect = lambda directory, value: records.append(copy.deepcopy(value))
        calls = []
        def sql(ctl_arg, rid_arg, state_arg, statement):
            calls.append(statement)
            if statement == 'SELECT @@global.max_connections':
                return '2'
            if statement.startswith('SELECT COUNT(*) FROM mysql.user'):
                return '0'
            if statement.startswith('SHOW GRANTS'):
                return 'GRANT USAGE ON *.* TO `' + name + '`@`localhost`'
            return ''
        fd_os = types.SimpleNamespace(memfd_create=lambda *a: 7, MFD_CLOEXEC=1,
                                      fchmod=Mock(), open=Mock(side_effect=[8, 9]),
                                      O_RDONLY=0, O_CLOEXEC=1,
                                      write=lambda fd, data: len(data), close=Mock())
        denied = b'ERROR 1045 (28000)' if fail_refusal else b'ERROR 1040 (08004)'
        responses = [subprocess.CompletedProcess([], 0, b'1\n', b''),
                     subprocess.CompletedProcess([], 1, b'', denied),
                     subprocess.CompletedProcess([], 0, b'1\n', b'')]
        with patch.object(p, 'target'), patch.object(p, 'query', side_effect=sql), \
             patch.object(p, 'os', fd_os), patch.object(p, 'one_client', side_effect=responses), \
             patch.object(p, 'wait_sleepers') as wait, patch.object(p, 'stop_holders') as stop, \
             patch.object(p.subprocess, 'Popen', side_effect=lambda *a, **k: Mock()) as spawn:
            if fail_refusal:
                with self.assertRaisesRegex(RuntimeError, 'no explicit MySQL 1040'):
                    p.exercise(ctl, rid, '.', state)
                self.assertEqual(state['m03_probe']['phase'], 'INJECTING')
                self.assertFalse(any(s.startswith('DROP USER') for s in calls))
            else:
                p.exercise(ctl, rid, '.', state)
                self.assertEqual(state['m03_probe']['phase'], 'ACCOUNT_REMOVED')
                self.assertTrue(any(s.startswith('DROP USER') for s in calls))
                self.assertEqual([x.args[-1] for x in wait.call_args_list], [2, 0])
                self.assertTrue(any(item['m03_probe'].get('error') == 1040 for item in records))
            self.assertEqual(records[0]['m03_probe']['phase'], 'CREATE_ATTEMPTED')
            self.assertEqual(spawn.call_count, 2)
            self.assertGreaterEqual(stop.call_count, 1)
            fd_os.fchmod.assert_called_once_with(7, 0o600)
            self.assertEqual([call.args[0] for call in fd_os.close.call_args_list], [8, 9, 7])
            self.assertEqual([call.kwargs['pass_fds'] for call in spawn.call_args_list], [(8,), (9,)])
            self.assertEqual(fd_os.open.call_count, 2)
            for call in spawn.call_args_list:
                self.assertIn('--protocol=SOCKET', call.args[0])
                self.assertNotIn(p.MARKER, repr(call.args[0]))

    def test_one_client_uses_a_new_read_handle_and_closes_it(self):
        ctl = Mock()
        ctl.ENV = {}
        ctl.paths.return_value = (None, None, '/isolated/mysql.sock')
        fake_os = types.SimpleNamespace(open=Mock(return_value=12), close=Mock(), O_RDONLY=0, O_CLOEXEC=1)
        result = subprocess.CompletedProcess([], 0, b'1\n', b'')
        with patch.object(p, 'os', fake_os), patch.object(p.subprocess, 'run', return_value=result) as run:
            self.assertIs(p.one_client(ctl, '0123456789abcdef', 'm03_test', 7), result)
        fake_os.open.assert_called_once_with('/proc/self/fd/7', 1)
        fake_os.close.assert_called_once_with(12)
        self.assertEqual(run.call_args.kwargs['pass_fds'], (12,))
        self.assertIn('--defaults-extra-file=/proc/self/fd/12', run.call_args.args[0])

    def test_chmod_failure_closes_memfd_before_client_is_started(self):
        rid = '0123456789abcdef'
        name = 'm03_' + rid
        ctl = Mock()
        def sql(ctl_arg, rid_arg, state_arg, statement):
            if statement.startswith('SELECT @@'):
                return '2'
            if statement.startswith('SELECT COUNT'):
                return '0'
            if statement.startswith('SHOW GRANTS'):
                return 'GRANT USAGE ON *.* TO `' + name + '`@`localhost`'
            return ''
        fake_os = types.SimpleNamespace(memfd_create=lambda *a: 7, MFD_CLOEXEC=1,
                                        fchmod=Mock(side_effect=OSError('chmod failed')), close=Mock())
        with patch.object(p, 'target'), patch.object(p, 'query', side_effect=sql), \
             patch.object(p, 'os', fake_os), patch.object(p, 'one_client') as client, \
             patch.object(p, 'stop_holders') as stop:
            with self.assertRaisesRegex(OSError, 'chmod failed'):
                p.exercise(ctl, rid, '.', {})
        client.assert_not_called()
        fake_os.close.assert_called_once_with(7)
        stop.assert_called_once_with([])

    def test_holders_continue_cleanup_after_error(self):
        first, second = Mock(), Mock()
        first.poll.return_value = None
        second.poll.return_value = 0
        with patch.object(p.os, 'killpg', side_effect=OSError('bad'), create=True):
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                p.stop_holders([first, second])
        second.stdin.close.assert_called_once()

    def test_start_failure_records_error_and_attempts_controller_reset(self):
        ctl = Mock()
        directory = Mock()
        ctl.BASE.__truediv__ = Mock(return_value=directory)
        ctl.locked.return_value = 42
        ctl.boot_context.return_value = ('boot', 100)
        ctl.start.side_effect = RuntimeError('start failed')
        saved = []
        ctl.save.side_effect = lambda d, state: saved.append(copy.deepcopy(state))
        fake_signal = types.SimpleNamespace(SIGALRM=14, ITIMER_REAL=0, getsignal=lambda _: None,
                                            signal=Mock(), setitimer=Mock())
        fake_os = types.SimpleNamespace(close=Mock())
        with patch.object(p, 'signal', fake_signal), patch.object(p, 'os', fake_os):
            with self.assertRaisesRegex(RuntimeError, 'start failed'):
                p.run_probe(ctl)
        ctl.reset.assert_called_once()
        fake_os.close.assert_called_once_with(42)
        self.assertEqual(saved[-1]['m03_error_type'], 'RuntimeError')


if __name__ == '__main__':
    unittest.main()
