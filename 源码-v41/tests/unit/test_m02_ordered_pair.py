import importlib.util
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, 'scripts')
spec = importlib.util.spec_from_file_location('m02_ordered_pair', 'scripts/m02_ordered_pair.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class EdgeTests(unittest.TestCase):
    def setUp(self):
        self.edge = dict(engine='INNODB', req_tid=100, blk_tid=101, req_pid=10, blk_pid=11,
                         req_user=m.WRITER, blk_user=m.WRITER, req_db=m.DB, blk_db=m.DB,
                         req_lock_tid=100, blk_lock_tid=101, req_schema=m.DB, blk_schema=m.DB,
                         req_table='orders', blk_table='orders', req_index='PRIMARY', blk_index='PRIMARY',
                         req_type='RECORD', blk_type='RECORD', req_mode='X,REC_NOT_GAP', blk_mode='X,REC_NOT_GAP',
                         req_status='WAITING', blk_status='GRANTED', req_data='10086', blk_data='10086',
                         req_trx=200, req_lock_trx=200, blk_trx=201, blk_lock_trx=201)

    def test_exact_wait_edge(self):
        with patch.object(m, 'dict_rows', return_value=[self.edge]):
            self.assertEqual(m.read_wait_edge_10086(None, 100, 101, 10, 11)['record_id'], 10086)

    def test_rejects_wrong_or_unknown_identity_and_lock(self):
        for key, value in [('req_pid', 99), ('req_data', None), ('blk_data', '10087'),
                           ('req_index', 'other'), ('req_status', 'GRANTED'), ('req_lock_trx', 999)]:
            edge = dict(self.edge, **{key: value})
            with self.subTest(key=key), patch.object(m, 'dict_rows', return_value=[edge]), self.assertRaises(m.DrillError):
                m.read_wait_edge_10086(None, 100, 101, 10, 11)

    def test_ambiguous_wait_edge_rejected(self):
        with patch.object(m, 'dict_rows', return_value=[self.edge, self.edge]), self.assertRaises(m.DrillError):
            m.read_wait_edge_10086(None, 100, 101, 10, 11)

    def test_active_transaction_requires_two_matching_observations(self):
        with patch.object(m.c1, 'admin_connect', side_effect=[MagicMock(), MagicMock(), MagicMock()]), \
             patch.object(m, 'thread_count', return_value=1), \
             patch.object(m.c1, 'count_transaction', side_effect=[0, 1, 1]), \
             patch.object(m.c1, 'count_thread_waits', return_value=0), patch.object(m.time, 'sleep'):
            observed = m.wait_for_active_transaction(10, 100)
        self.assertEqual([x['transaction_count'] for x in observed], [0, 1, 1])

    def test_missing_active_transaction_never_passes(self):
        with patch.object(m.c1, 'admin_connect', return_value=MagicMock()), \
             patch.object(m, 'thread_count', return_value=1), \
             patch.object(m.c1, 'count_transaction', return_value=0), \
             patch.object(m.c1, 'count_thread_waits', return_value=0), self.assertRaises(m.DrillError):
            m.wait_for_active_transaction(10, 100, timeout=0)


if __name__ == '__main__': unittest.main()
