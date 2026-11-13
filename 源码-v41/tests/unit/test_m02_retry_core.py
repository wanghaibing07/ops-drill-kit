import importlib.util
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, 'scripts')
spec = importlib.util.spec_from_file_location('m02_retry_core', 'scripts/m02_retry_core.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RetryTests(unittest.TestCase):
    def run_case(self, code):
        a, b = MagicMock(), MagicMock()
        locks = []
        def lock(conn, order_id):
            locks.append((conn, order_id))
            if conn is a and order_id == 10087:
                raise m.pymysql.err.OperationalError(code, 'redacted')
            return 3
        with patch.object(m.base, 'connect_writer', side_effect=[a, b]) as connect, \
             patch.object(m.base, 'validate_writer', side_effect=[10, 11]), \
             patch.object(m, 'set_session_timeout'), patch.object(m, 'lock_one', side_effect=lock), \
             patch.object(m, 'update_one', return_value=1), \
             patch.object(m, 'read_statuses', return_value={10086: 4, 10087: 4}), \
             patch.object(m.time, 'sleep'):
            result = m.run_ordered_transaction_with_retry()
        self.assertEqual(result['attempts_used'], 2)
        self.assertEqual(result['history'][0]['error_code'], code)
        self.assertEqual(locks, [(a, 10086), (a, 10087), (b, 10086), (b, 10087)])
        self.assertEqual(connect.call_count, 2)
        a.rollback.assert_called_once(); b.rollback.assert_called_once()
        a.close.assert_called_once(); b.close.assert_called_once()

    def test_timeout_restarts_whole_transaction(self):
        self.run_case(1205)

    def test_deadlock_restarts_whole_transaction(self):
        self.run_case(1213)

    def test_non_retryable_error_rolls_back_without_retry(self):
        conn = MagicMock()
        with patch.object(m.base, 'connect_writer', return_value=conn) as connect, \
             patch.object(m.base, 'validate_writer', return_value=10), patch.object(m, 'set_session_timeout'), \
             patch.object(m, 'lock_one', side_effect=m.pymysql.err.OperationalError(1142, 'redacted')):
            with self.assertRaises(m.RetryFailure): m.run_ordered_transaction_with_retry()
        self.assertEqual(connect.call_count, 1)
        conn.rollback.assert_called_once(); conn.close.assert_called_once()

    def test_non_mysql_exception_also_rolls_back(self):
        conn = MagicMock()
        with patch.object(m.base, 'connect_writer', return_value=conn), \
             patch.object(m.base, 'validate_writer', return_value=10), patch.object(m, 'set_session_timeout'), \
             patch.object(m, 'lock_one', side_effect=ValueError('test')):
            with self.assertRaises(ValueError): m.run_ordered_transaction_with_retry()
        conn.rollback.assert_called_once(); conn.close.assert_called_once()

    def test_retry_limit_stops_after_three_attempts(self):
        conns = [MagicMock(), MagicMock(), MagicMock()]
        with patch.object(m.base, 'connect_writer', side_effect=conns) as connect, \
             patch.object(m.base, 'validate_writer', side_effect=[10, 11, 12]), \
             patch.object(m, 'set_session_timeout'), patch.object(m.time, 'sleep'), \
             patch.object(m, 'lock_one', side_effect=m.pymysql.err.OperationalError(1205, 'redacted')):
            with self.assertRaises(m.RetryFailure) as failure: m.run_ordered_transaction_with_retry()
        self.assertEqual(connect.call_count, 3)
        self.assertEqual(len(failure.exception.history), 3)
        for conn in conns:
            conn.rollback.assert_called_once(); conn.close.assert_called_once()

    def test_rollback_failure_prevents_retry(self):
        conn = MagicMock(); conn.rollback.side_effect = OSError('redacted')
        with patch.object(m.base, 'connect_writer', return_value=conn) as connect, \
             patch.object(m.base, 'validate_writer', return_value=10), patch.object(m, 'set_session_timeout'), \
             patch.object(m, 'lock_one', side_effect=m.pymysql.err.OperationalError(1205, 'redacted')):
            with self.assertRaises(m.RetryFailure): m.run_ordered_transaction_with_retry()
        self.assertEqual(connect.call_count, 1)
        conn.close.assert_called_once()


if __name__ == '__main__': unittest.main()
