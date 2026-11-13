import ast,json,re,unittest
from pathlib import Path
source=(Path(__file__).resolve().parents[2]/'tests/contract/C01-window-metrics.py').read_text(encoding='utf8');tree=ast.parse(source)
nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in ('PendingLog','parse_log_window')]
module=ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[]));ns={'json':json,'re':re};exec(compile(module,'window-functions','exec'),ns)
parse=ns['parse_log_window'];PendingLog=ns['PendingLog'];A='a'*32;B='b'*32
def line(request_id,status):return (json.dumps({'request_id':request_id,'status':status})+'\n').encode()
class WindowLogTests(unittest.TestCase):
 def test_complete_window_counts_all_rows(self):
  counts,total,matched=parse(line(A,200)+line(B,503),{A:200});self.assertEqual(counts,{'200':1,'503':1});self.assertEqual((total,matched),(2,1))
 def test_incomplete_or_missing_is_pending(self):
  for raw in (b'',line(A,200)[:-1],line(B,200)):
   with self.subTest(raw=raw),self.assertRaises(PendingLog):parse(raw,{A:200})
 def test_duplicate_mismatch_and_corrupt_lines_fail(self):
  for raw in (line(A,200)+line(A,200),line(A,502),b'{broken}\n',line('bad',200)):
   with self.subTest(raw=raw),self.assertRaises((AssertionError,ValueError)):parse(raw,{A:200})
if __name__=='__main__':unittest.main()
