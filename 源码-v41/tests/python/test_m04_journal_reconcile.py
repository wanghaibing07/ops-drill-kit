import importlib.util,json,subprocess,types,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
MODULE=ROOT/'experimental/m04/synthetic-v4/continuation/mysql_lifecycle_candidate.py'
spec=importlib.util.spec_from_file_location('m04_v4_lifecycle_test',MODULE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class JournalStopTests(unittest.TestCase):
 def setUp(self):
  self.rid='a'*16;self.unit='opsdrill-m04-target-'+self.rid+'.service';self.boot='11111111-2222-3333-4444-555555555555';self.inv='b'*32
  self.rec=types.SimpleNamespace(unit=self.unit,boot_id=self.boot,invocation_id=self.inv,pid=98765,control_group='/system.slice/'+self.unit)
  self.start={'MESSAGE_ID':'39f53479d3a045ac8e11786248231fbf','_PID':'1','_UID':'0','_BOOT_ID':self.boot.replace('-',''),'UNIT':self.unit,'INVOCATION_ID':self.inv,'JOB_RESULT':'done','__MONOTONIC_TIMESTAMP':'100'}
  self.stop=dict(self.start,MESSAGE_ID='9d1aaa27d60140bd96365438aad20286',__MONOTONIC_TIMESTAMP='200')
  self.rows=[self.start,self.stop];self.exists=False
  self.patches=[patch.object(m.ctl,'require_same_boot'),patch.object(m,'records_from_state',return_value={'target':self.rec}),patch.object(m.ctl,'properties',return_value={'LoadState':'not-found','ActiveState':'inactive'}),patch.object(m.ctl,'paths',return_value=(None,None,'/fake/socket')),patch.object(m.os.path,'lexists',side_effect=lambda p:self.exists),patch.object(m.subprocess,'run',side_effect=self.fake_journal)]
  for p in self.patches:p.start();self.addCleanup(p.stop)
 def fake_journal(self,*args,**kwargs):return types.SimpleNamespace(returncode=0,stdout=b''.join((json.dumps(x)+'\n').encode() for x in self.rows))
 def test_matching_start_stop_and_absent_resources(self):self.assertTrue(m.stopped_by_journal(self.rid,{},'target'))
 def test_wrong_identity_or_incomplete_evidence_is_refused(self):
  for key,value in (('INVOCATION_ID','c'*32),('_BOOT_ID','d'*32),('_PID','2'),('_UID','1000'),('JOB_RESULT','failed')):
   with self.subTest(key=key):
    self.rows=[self.start,dict(self.stop,**{key:value})]
    with self.assertRaises(Exception):m.stopped_by_journal(self.rid,{},'target')
  for rows in ([self.start],[self.start,self.stop,self.stop],[self.start,dict(self.stop,__MONOTONIC_TIMESTAMP='99')]):
   self.rows=rows
   with self.assertRaises(Exception):m.stopped_by_journal(self.rid,{},'target')
 def test_remaining_process_or_socket_is_refused(self):
  self.exists=True
  with self.assertRaises(Exception):m.stopped_by_journal(self.rid,{},'target')
 def test_unavailable_or_bad_journal_is_refused(self):
  for q in (types.SimpleNamespace(returncode=1,stdout=b''),types.SimpleNamespace(returncode=0,stdout=b'{broken}\n')):
   with patch.object(m.subprocess,'run',return_value=q),self.assertRaises(Exception):m.stopped_by_journal(self.rid,{},'target')

if __name__=='__main__':unittest.main()
