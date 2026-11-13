import subprocess
import unittest
from unittest.mock import Mock, patch

import m03_candidate as m


class CandidateTests(unittest.TestCase):
    def drill(self, phase):
        drill = object.__new__(m.Drill)
        drill.phase = phase
        drill.holders = []
        drill.server = None
        return drill

    def test_only_explicit_capacity_error_is_exhaustion(self):
        self.assertTrue(m.status_from_error(1, b'ERROR 1040 (08004): Too many connections'))
        for code, error in ((0, b'ERROR 1040 (08004)'), (1, b'ERROR 1045 (28000)'), (1, b'connection failed')):
            self.assertFalse(m.status_from_error(code, error))

    def test_injected_and_released_database_checks_do_not_claim_overall_pass(self):
        for phase, counts, result in (
            ('INJECTED', ['Threads_connected\t11', 'Threads_running\t1', '10'],
             subprocess.CompletedProcess([], 1, b'', b'ERROR 1040 (08004)')),
            ('RELEASED', ['Threads_connected\t1', 'Threads_running\t1', '0'],
             subprocess.CompletedProcess([], 0, b'1\n', b'')),
            ('RELEASED', ['Threads_connected\t9', 'Threads_running\t1', '0'],
             subprocess.CompletedProcess([], 0, b'1\n', b'')),
        ):
            drill = self.drill(phase)
            drill.verify = Mock()
            drill.admin = Mock(side_effect=counts)
            drill.command = Mock(return_value=result)
            report = drill.check()
            self.assertEqual(report['database_check'], 'FAIL' if counts[0].endswith('\t9') else 'PASS')
            self.assertEqual(report['overall'], 'INCOMPLETE')
            self.assertEqual(report['api_readiness'], 'NOT_TESTED')

    def test_injection_is_bounded_and_refuses_wrong_phase(self):
        drill = self.drill('READY')
        drill.verify = Mock()
        drill.socket, drill.option = '/tmp/test/mysql.sock', '/tmp/test/client.cnf'
        with patch.object(m.subprocess, 'Popen', side_effect=lambda *a, **k: Mock()) as spawn:
            drill.inject()
            self.assertEqual(spawn.call_count, m.HOLDER_COUNT)
            for call in spawn.call_args_list:
                args = call.args[0]
                self.assertEqual(args[0], m.TIMEOUT)
                self.assertIn('--protocol=SOCKET', args)
                self.assertIn('--socket=/tmp/test/mysql.sock', args)
                self.assertNotIn(m.MARKER, repr(args))
        with self.assertRaises(m.SafetyError):
            drill.inject()

    def test_reset_tries_every_owned_process_and_reports_failure(self):
        drill = self.drill('INJECTED')
        drill.holders, drill.server = [Mock(), Mock()], Mock()
        drill.stop_process = Mock(side_effect=[OSError('failure'), None, None])
        with self.assertRaises(m.SafetyError):
            drill.reset()
        self.assertEqual(drill.stop_process.call_count, 3)
        self.assertEqual(drill.phase, 'RESET_FAILED')

    def test_identity_mismatch_refuses_even_if_server_running(self):
        drill = self.drill('READY')
        drill.server = Mock()
        drill.server.poll.return_value = None
        from pathlib import Path
        drill.data, drill.socket, drill.uuid = Path('/private/data'), Path('/private/mysql.sock'), None
        drill.admin = Mock(return_value='/wrong\t/private/mysql.sock\t1\t10\t12345678-1234-1234-1234-123456789abc')
        with self.assertRaises(m.SafetyError):
            drill.verify()

    def test_entry_point_remains_disabled(self):
        with self.assertRaisesRegex(m.SafetyError, 'disabled'):
            m.main()


if __name__ == '__main__':
    unittest.main()
