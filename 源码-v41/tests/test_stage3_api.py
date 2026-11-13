import json
import os
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from fastapi import HTTPException
from app import stage3_api


class FakeCursor:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchone(self):
        return {'total': 1}

    def fetchall(self):
        return [{'order_no': 'OG000000000020'}]


class FakeConnection:
    def __init__(self):
        self.cur = FakeCursor()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def cursor(self):
        return self.cur


class Stage3UnitTests(unittest.TestCase):
    def test_uses_read_only_transaction_and_bound_parameters(self):
        conn = FakeConnection()
        with patch.object(stage3_api, 'get_stage3_connection', return_value=conn):
            result = stage3_api.list_orders(88, 3, 20)
        self.assertEqual(result['total'], 1)
        self.assertEqual(conn.cur.calls[0][0], 'START TRANSACTION READ ONLY')
        self.assertEqual(conn.cur.calls[1][1], (88,))
        self.assertEqual(conn.cur.calls[2][1], (88, 20, 40))

    def test_database_failure_returns_503(self):
        with patch.object(stage3_api, 'get_stage3_connection', side_effect=OSError('offline')):
            with self.assertRaises(HTTPException) as caught:
                stage3_api.list_orders(88, 1, 20)
        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(caught.exception.detail, 'Database unavailable')


@unittest.skipUnless(os.environ.get('ORDERGUARD_INTEGRATION_URL'), 'live service not requested')
class Stage3LiveTests(unittest.TestCase):
    def get(self, path):
        url = os.environ['ORDERGUARD_INTEGRATION_URL'].rstrip('/') + path
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.load(response)

    def test_pagination_and_legacy_endpoint(self):
        first = self.get('/api/v1/orders?merchant_id=88&page=1&page_size=20')
        second = self.get('/api/v1/orders?merchant_id=88&page=2&page_size=20')
        first_ids = {row['order_no'] for row in first['items']}
        second_ids = {row['order_no'] for row in second['items']}
        self.assertEqual((first['total'], second['total']), (25000, 25000))
        self.assertEqual((len(first_ids), len(second_ids)), (20, 20))
        self.assertFalse(first_ids & second_ids)
        self.assertEqual(self.get('/orders/1001')['amount'], '99.00')

    def test_invalid_and_unknown_merchant(self):
        self.assertEqual(self.get('/api/v1/orders?merchant_id=999999')['total'], 0)
        for query in ('merchant_id=0', 'merchant_id=88&page_size=101', ''):
            with self.subTest(query=query):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    self.get('/api/v1/orders?' + query)
                self.assertEqual(caught.exception.code, 422)


if __name__ == '__main__':
    unittest.main()
