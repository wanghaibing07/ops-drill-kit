"""Offline-only tests for fasttrack's run ownership receipt parser."""
import importlib.util
import json
import unittest
from pathlib import Path

FILE=Path(__file__).resolve().parents[2]/'scripts/l03_fasttrack_guard.py'
spec=importlib.util.spec_from_file_location('l03_fasttrack_guard',str(FILE))
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)

class ReceiptTests(unittest.TestCase):
    def receipt(self, rid='a'*24, **extra):
        obj={'receipt':g.RECEIPT,'run_id':rid,'unit':'opsdrill-l03-'+rid+'.service'}
        obj.update(extra)
        return (json.dumps(obj)+'\n').encode()

    def test_valid_receipt(self):
        rid='a'*24
        self.assertEqual(g.parse_receipt_bytes(self.receipt()),
                         (rid,'opsdrill-l03-'+rid+'.service'))

    def test_empty_receipt_rejected(self):
        with self.assertRaisesRegex(ValueError,'RECEIPT_SIZE'):
            g.parse_receipt_bytes(b'')

    def test_malformed_json_rejected(self):
        with self.assertRaises(json.JSONDecodeError):
            g.parse_receipt_bytes(b'{not-json}\n')

    def test_two_json_lines_rejected(self):
        raw=self.receipt()+self.receipt('b'*24)
        with self.assertRaisesRegex(ValueError,'RECEIPT_LINE_COUNT'):
            g.parse_receipt_bytes(raw)

    def test_duplicate_json_key_rejected(self):
        rid='a'*24
        raw=(f'{{"receipt":"{g.RECEIPT}","run_id":"{rid}","run_id":"{rid}",'
             f'"unit":"opsdrill-l03-{rid}.service"}}\n').encode()
        with self.assertRaisesRegex(ValueError,'RECEIPT_DUPLICATE_KEY'):
            g.parse_receipt_bytes(raw)

    def test_wrong_receipt_type_rejected(self):
        raw=json.loads(self.receipt())
        raw['receipt']='STARTED'
        with self.assertRaisesRegex(ValueError,'RECEIPT_ID'):
            g.parse_receipt_bytes((json.dumps(raw)+'\n').encode())

    def test_bad_run_id_rejected(self):
        with self.assertRaisesRegex(ValueError,'RECEIPT_ID'):
            g.parse_receipt_bytes(self.receipt('../bad'))

    def test_wrong_unit_rejected(self):
        with self.assertRaisesRegex(ValueError,'RECEIPT_UNIT'):
            g.parse_receipt_bytes(self.receipt(unit='opsdrill-l03-'+'b'*24+'.service'))

    def test_extra_fields_rejected(self):
        with self.assertRaisesRegex(ValueError,'RECEIPT_SCHEMA'):
            g.parse_receipt_bytes(self.receipt(extra='unexpected'))

if __name__=='__main__': unittest.main()
