import hashlib
import unittest
import importlib.util
from pathlib import Path
_path=Path(__file__).resolve().parents[2]/'baseline/db_batch.py'
_spec=importlib.util.spec_from_file_location('baseline_db_batch',_path)
_mod=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_mod)
parse_batch,statements=_mod.parse_batch,_mod.statements

class BatchTests(unittest.TestCase):
    def row(self, order='OG000000000001', merchant='169', amount='39186', channel='wallet'):
        return f'{order}\t{merchant}\t29529\t4\t{amount}\t{channel}\t2026-07-23 08:28:39\t2026-07-23 09:00:51\n'.encode()

    def parsed(self, data):
        return parse_batch(data, 1, 1, hashlib.sha256(data).hexdigest())

    def test_valid_row_and_fixed_sql(self):
        sql=list(statements(self.parsed(self.row())))
        self.assertEqual(len(sql),1)
        self.assertIn("('OG000000000001',169,29529,4,39186,'wallet'",sql[0])
        self.assertNotIn('LOCAL INFILE',sql[0])

    def test_wrong_digest_is_refused(self):
        with self.assertRaises(ValueError): parse_batch(self.row(),1,1,'0'*64)

    def test_invalid_fields_are_refused_even_with_matching_digest(self):
        for data in (self.row(order='OG000000000002'),self.row(merchant='88'),
                     self.row(amount='0'),self.row(channel="x'); DROP TABLE orders;--"),
                     self.row().replace(b'2026-07-23 09:00:51',b'2026-02-31 09:00:51'),
                     self.row()[:-1]):
            with self.subTest(data=data):
                with self.assertRaises(ValueError): self.parsed(data)

    def test_probe_embeds_reviewed_parser(self):
        import ast,base64
        source=(_path.parent/'isolated_mysql_probe.py').read_text(encoding='utf8')
        tree=ast.parse(source)
        encoded=next(n.args[0].value for n in ast.walk(tree) if isinstance(n,ast.Call)
                     and isinstance(n.func,ast.Attribute) and n.func.attr=='b64decode'
                     and len(n.args)==1 and isinstance(n.args[0],ast.Constant))
        self.assertEqual(base64.b64decode(encoded),_path.read_bytes())

if __name__=='__main__': unittest.main()
