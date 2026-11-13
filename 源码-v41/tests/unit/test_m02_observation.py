import importlib.util
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('m02_deadlock', 'scripts/m02_deadlock.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.tids = {10: 100, 11: 101}
        self.row = ['INNODB', 100, 101, 1000, 1001, 10, 11,
                    'INNODB', 1000, 'orderguard_stage3', 'orders', 'PRIMARY', 'RECORD', 'X,REC_NOT_GAP', 'WAITING', '10087',
                    'INNODB', 1001, 'orderguard_stage3', 'orders', 'PRIMARY', 'RECORD', 'X,REC_NOT_GAP', 'GRANTED', '10087']

    def test_valid_edge_and_no_edge(self):
        self.assertEqual(m.validate_ps_edge(self.row, 10, 11, self.tids)['target_primary_key'], 10087)
        self.assertIsNone(m.validate_ps_edge(None, 10, 11, self.tids))

    def test_rejects_wrong_identity_or_target(self):
        for index, bad in ((1, 999), (5, 999), (9, 'other'), (11, 'other'), (13, 'S'), (14, 'GRANTED'), (15, None), (24, '10086')):
            row = self.row.copy(); row[index] = bad
            with self.subTest(index=index), self.assertRaises(m.DrillError):
                m.validate_ps_edge(row, 10, 11, self.tids)

    def test_multiple_wait_edges_are_rejected(self):
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchall.return_value = [self.row, self.row]
        with self.assertRaises(m.DrillError):
            m.ps_wait_edge(conn, 10, 11, self.tids)

    def test_recovery_requires_two_consecutive_clean_samples(self):
        expected = {10086: 3, 10087: 3}
        with patch.object(m, 'target_status', return_value=expected), patch.object(m, 'transaction_count', side_effect=[1, 0, 0]), patch.object(m, 'ps_wait_count', return_value=0), patch.object(m.time, 'sleep'):
            passed, samples = m.bounded_recovery(None, [10,11], [100,101], expected)
        self.assertTrue(passed)
        self.assertEqual([s['transactions'] for s in samples], [1, 0, 0])

    def test_persistent_wait_never_passes(self):
        expected = {10086: 3, 10087: 3}
        with patch.object(m, 'target_status', return_value=expected), patch.object(m, 'transaction_count', return_value=0), patch.object(m, 'ps_wait_count', return_value=1), patch.object(m.time, 'sleep'):
            passed, samples = m.bounded_recovery(None, [10,11], [100,101], expected, timeout=0)
        self.assertFalse(passed)
        self.assertEqual(samples[-1]['waits'], 1)


if __name__ == '__main__':
    unittest.main()
