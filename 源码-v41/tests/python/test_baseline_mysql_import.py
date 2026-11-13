import hashlib,importlib.util,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
stage=Path(__file__).resolve().parents[2]/'baseline'
path=stage/'mysql_import.py'
sys.path.insert(0,str(stage));spec=importlib.util.spec_from_file_location('candidate_unit',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class TestCandidate(unittest.TestCase):
 def setUp(self):
  raw=b'abc';sha=hashlib.sha256(raw).hexdigest();empty=hashlib.sha256(b'').hexdigest()
  self.entry={'start':1,'end':1,'source_sha256':sha,'before_sha256':empty,'after_sha256':sha}
  self.state={'version':1,'run_id':'a'*24,'actor':'agent','server_uuid':'id','status':'DONE','committed':[self.entry], 'schema_sha256':{'table':'digest'}}
  self.patches=[patch.object(m.c,'guard'),patch.object(m.c,'chain'),patch.object(m.c,'regular'),patch.object(m,'load_verifier'),patch.object(m,'require_network'),patch.object(m,'identity',return_value='id'),patch.object(m,'batches_preflight',return_value=(1000,[(1,1,'batch',sha)])),patch.object(m,'schema_sources',return_value=[]),patch.object(m,'sql',return_value=b'2'),patch.object(m,'read_journal',side_effect=lambda:self.state),patch.object(m,'file_bytes',return_value=raw),patch.object(m,'verify_data',return_value={'table':'digest'})]
  for p in self.patches:p.start();self.addCleanup(p.stop)
 def test_complete_valid_record(self):self.assertEqual(m.preflight()[0],'same')
 def test_duplicate_keys_at_any_depth(self):
  for text in ('{"a":1,"a":2}','{"x":{"a":1,"a":2}}'):
   with self.subTest(text=text),self.assertRaises(ValueError):json.loads(text,object_pairs_hook=m.unique_object)
 def test_existing_databases_without_journal_rejected(self):
  self.state=None
  with self.assertRaises(m.c.Refusal):m.preflight()
 def test_unfinished_and_foreign_server_rejected(self):
  for change in ({'status':'IMPORTING'},{'server_uuid':'different'}):
   with self.subTest(change=change):
    old=self.state.copy();self.state.update(change)
    with self.assertRaises(m.c.Refusal):m.preflight()
    self.state=old
 def test_tampered_batch_rejected(self):
  self.state['committed']=[dict(self.entry,after_sha256='0'*64)]
  with self.assertRaises(m.c.Refusal):m.preflight()
 def test_schema_change_rejected(self):
  self.state['schema_sha256']={'table':'other'}
  with self.assertRaises(m.c.Refusal):m.preflight()
 def test_incomplete_or_extra_fields_rejected(self):
  for state in (dict(self.state,committed=[]),dict(self.state,unexpected=True),dict(self.state,actor='unknown')):
   with self.subTest(state=state):
    self.state=state
    with self.assertRaises(m.c.Refusal):m.preflight()
class TestProcessBinding(unittest.TestCase):
 def setUp(self):m._PROCESS_IDENTITY=None;self.addCleanup(setattr,m,'_PROCESS_IDENTITY',None)
 def test_same_uuid_with_changed_process_is_refused(self):
  data=b'11111111-1111-1111-1111-111111111111\t/var/lib/mysql/\t/var/lib/mysql/mysql.sock\t8.4.13\t0\n'
  old=('boot','invocation-a','42','100');new=('boot','invocation-b','42','200')
  with patch.object(m,'sql',return_value=data),patch.object(m,'process_identity',side_effect=[old,old,new]):
   self.assertEqual(m.identity(),'11111111-1111-1111-1111-111111111111')
   with self.assertRaises(m.c.Refusal):m.identity()
 def test_change_during_identity_query_is_refused(self):
  with patch.object(m,'sql',return_value=b'ignored'),patch.object(m,'process_identity',side_effect=[('a',),('b',)]):
   with self.assertRaises(m.c.Refusal):m.identity()
if __name__=='__main__':unittest.main(verbosity=2)
