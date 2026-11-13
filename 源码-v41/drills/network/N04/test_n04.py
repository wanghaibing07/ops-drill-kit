import contextlib
import errno
import io
import json
import unittest
from unittest.mock import MagicMock, patch

import n04


class N04Tests(unittest.TestCase):
    def test_namespace_must_differ_from_parent_and_initial(self):
        for values in [[(1, 2), (1, 2), (1, 3)], [(1, 2), (1, 3), (1, 2)]]:
            with self.subTest(values=values), patch.object(n04, 'namespace_identity', side_effect=values):
                with self.assertRaises(RuntimeError):
                    n04.require_isolation()
        with patch.object(n04, 'namespace_identity', side_effect=[(1, 2), (1, 3), (1, 3)]):
            self.assertEqual(n04.require_isolation(), (1, 2))

    def test_sysctl_is_never_written_when_namespace_identity_changes(self):
        path = MagicMock()
        with patch.object(n04, 'SYSCTL', path), patch.object(n04, 'require_isolation', return_value=(1, 4)):
            with self.assertRaises(RuntimeError):
                n04.set_range((n04.LOW, n04.HIGH), (1, 3))
        path.write_text.assert_not_called()

    def test_range_validation(self):
        self.assertEqual(n04.port_range('32768\t60999\n'), (32768, 60999))
        for text in ('1 1', '0 2', '1 65536', '1 2 3', '-1 4', '١ 2'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                n04.port_range(text)

    def test_timewait_filters_address_port_and_state(self):
        lines = ('header\n'
                 '0: 0100007F:9C40 0200007F:46A0 06\n'
                 '1: 0100007F:9C41 0200007F:46A0 01\n'
                 '2: 0100007F:9C60 0200007F:46A0 06\n'
                 '3: 0100007F:9C40 0100007F:46A0 06\n')
        self.assertEqual(n04.timewait_count(lines), 1)

    def test_fault_requires_exhaustion_timewait_and_expected_range(self):
        result = {'completed': 32, 'address_unavailable': 1, 'other_errors': []}
        self.assertTrue(n04.fault_evidence(result, 1, (n04.LOW, n04.HIGH)))
        for changed, count, observed in [
            (dict(result, address_unavailable=0), 1, (n04.LOW, n04.HIGH)),
            (dict(result, other_errors=[errno.ECONNREFUSED]), 1, (n04.LOW, n04.HIGH)),
            (result, 0, (n04.LOW, n04.HIGH)),
            (result, 1, (32768, 60999)),
        ]:
            self.assertFalse(n04.fault_evidence(changed, count, observed))

    def test_churn_is_bounded_and_classifies_address_exhaustion(self):
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.connect.side_effect = OSError(errno.EADDRNOTAVAIL, 'unavailable')
        with patch.object(n04.socket, 'socket', return_value=conn):
            result = n04.short_connections(n04.time.monotonic() + 2)
        self.assertEqual(result['attempts'], 1)
        self.assertEqual(result['address_unavailable'], 1)
        self.assertEqual(result['other_errors'], [])

    def test_churn_does_not_claim_unrelated_failure_as_exhaustion(self):
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.connect.side_effect = OSError(errno.ECONNREFUSED, 'refused')
        with patch.object(n04.socket, 'socket', return_value=conn):
            result = n04.short_connections(n04.time.monotonic() + 2)
        self.assertEqual(result['address_unavailable'], 0)
        self.assertEqual(result['other_errors'], [errno.ECONNREFUSED])

    def test_churn_has_fixed_connection_limit(self):
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.recv.return_value = b''
        with patch.object(n04.socket, 'socket', return_value=conn) as factory, \
             patch.object(n04, 'exchange'):
            result = n04.short_connections(n04.time.monotonic() + 5)
        self.assertEqual(factory.call_count, n04.MAX_ATTEMPTS)
        self.assertEqual(result['completed'], n04.MAX_ATTEMPTS)
        self.assertEqual(result['address_unavailable'], 0)

    def test_reuse_eight_exchanges_on_one_socket(self):
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.recv.side_effect = [b'x'] * 8 + [b'']
        with patch.object(n04.socket, 'socket', return_value=conn) as factory:
            self.assertEqual(n04.reuse_connection(), 8)
        factory.assert_called_once_with()
        self.assertEqual(conn.connect.call_count, 1)
        self.assertEqual(conn.sendall.call_count, 8)

    def test_session_restores_range_on_end_and_handles_buffered_commands(self):
        state = {'range': (32768, 60999)}
        listener = MagicMock()
        listener.__enter__.return_value = listener
        churn = {'attempts': 33, 'completed': 32, 'address_unavailable': 1, 'other_errors': []}
        output = io.StringIO()
        fake_in = MagicMock()
        fake_in.fileno.return_value = 10
        def write_range(value, identity):
            self.assertEqual(identity, (1, 2))
            state['range'] = value
        with patch.object(n04, 'require_isolation', return_value=(1, 2)), \
             patch.object(n04, 'read_range', side_effect=lambda: state['range']), \
             patch.object(n04, 'set_range', side_effect=write_range), \
             patch.object(n04.subprocess, 'run'), patch.object(n04.socket, 'socket', return_value=listener), \
             patch.object(n04.threading, 'Thread'), patch.object(n04, 'short_connections', return_value=churn), \
             patch.object(n04, 'reuse_connection', return_value=8), patch.object(n04, 'timewait_count', return_value=32), \
             patch.object(n04.Path, 'read_text', return_value='fake'), patch.object(n04.sys, 'stdin', fake_in), \
             patch.object(n04.select, 'select', return_value=([fake_in], [], [])), \
             patch.object(n04.os, 'read', return_value=b'check\nrepair\nreset\n'), contextlib.redirect_stdout(output):
            n04.worker()
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([item['event'] for item in events], ['injected', 'check', 'repair', 'reset'])
        self.assertTrue(events[1]['fault_proven'])
        self.assertTrue(events[2]['reuse_passed'])
        self.assertTrue(events[3]['range_restored'])
        self.assertEqual(state['range'], (32768, 60999))
        listener.close.assert_called_once()

    def test_failed_write_verification_attempts_restoration(self):
        state = {'range': (32768, 60999)}
        listener = MagicMock()
        def write_range(value, identity):
            state['range'] = value
            if value == (n04.LOW, n04.HIGH):
                raise RuntimeError('verification failed after write')
        with patch.object(n04, 'require_isolation', return_value=(1, 2)), \
             patch.object(n04, 'read_range', side_effect=lambda: state['range']), \
             patch.object(n04, 'set_range', side_effect=write_range), \
             patch.object(n04.subprocess, 'run'), patch.object(n04.socket, 'socket', return_value=listener), \
             patch.object(n04.threading, 'Thread'), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'verification failed'):
                n04.worker()
        self.assertEqual(state['range'], (32768, 60999))
        listener.close.assert_called_once()

    def test_foreign_range_drift_is_not_overwritten(self):
        state = {'range': (32768, 60999)}
        listener = MagicMock()
        writes = []
        def write_range(value, identity):
            writes.append(value)
            state['range'] = value
        def drift_then_fail(deadline):
            state['range'] = (20000, 30000)
            raise RuntimeError('interrupted')
        with patch.object(n04, 'require_isolation', return_value=(1, 2)), \
             patch.object(n04, 'read_range', side_effect=lambda: state['range']), \
             patch.object(n04, 'set_range', side_effect=write_range), \
             patch.object(n04.subprocess, 'run'), patch.object(n04.socket, 'socket', return_value=listener), \
             patch.object(n04.threading, 'Thread'), patch.object(n04, 'short_connections', side_effect=drift_then_fail), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'range drift'):
                n04.worker()
        self.assertEqual(writes, [(n04.LOW, n04.HIGH)])
        self.assertEqual(state['range'], (20000, 30000))

    def test_narrow_baseline_rejected_before_network_change(self):
        with patch.object(n04, 'require_isolation', return_value=(1, 2)), \
             patch.object(n04, 'read_range', return_value=(40000, 40031)), \
             patch.object(n04.subprocess, 'run') as run, patch.object(n04, 'set_range') as write:
            with self.assertRaisesRegex(RuntimeError, 'baseline'):
                n04.worker()
        run.assert_not_called()
        write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
