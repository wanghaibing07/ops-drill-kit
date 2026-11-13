import hashlib,importlib.util,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('audit_c01',ROOT/'scripts/audit_c01_window.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class AuditTests(unittest.TestCase):
 def logs(self,code=200):
  return b''.join((json.dumps({'request_id':format(i,'032x'),'status':code})+'\n').encode() for i in range(10))
 def test_log_hash_identity_and_status_fail_closed(self):
  raw=self.logs();sha=hashlib.sha256(raw).hexdigest();self.assertEqual(m.audit_rows(raw,'baseline',10,sha),10)
  with self.assertRaises(m.Refused):m.audit_rows(raw,'baseline',10,'0'*64)
  altered=self.logs(502)
  with self.assertRaises(m.Refused):m.audit_rows(altered,'baseline',10,hashlib.sha256(altered).hexdigest())
  duplicate=raw+raw.splitlines(keepends=True)[0]
  with self.assertRaises(m.Refused):m.audit_rows(duplicate,'baseline',11,hashlib.sha256(duplicate).hexdigest())
 def snapshots(self):
  errors={k:0 for k in ('closed','timeout','factory','ping','rollback','close','borrower')}
  def pool(t):return {'generation':'a'*32,'monotonic_ns':t,'capacity':4,'closed':False,'quarantined':0,'errors':dict(errors)}
  service={'ActiveState':'active','MainPID':'123','InvocationID':'b'*32}
  def snap(t):return {'service':dict(service),'body':{'scope':'single-process-lab','pid':123,'legacy':pool(t),'stage3':pool(t)}}
  return snap(10),snap(30)
 def test_pool_generation_counter_and_window(self):
  a,b=self.snapshots();self.assertEqual(m.audit_pools(a,b,15,25),'b'*32)
  for change in ('generation','errors','time','pid'):
   a,b=self.snapshots()
   if change=='generation':b['body']['stage3']['generation']='c'*32
   if change=='errors':b['body']['legacy']['errors']['timeout']=1
   if change=='time':b['body']['legacy']['monotonic_ns']=24
   if change=='pid':b['body']['pid']=124
   with self.subTest(change=change),self.assertRaises(m.Refused):m.audit_pools(a,b,15,25)
 def test_journal_identity_and_error_marker(self):
  boot='12345678-1234-1234-1234-123456789abc';inv='a'*32
  rows=[{'_BOOT_ID':boot.replace('-',''),'_SYSTEMD_INVOCATION_ID':inv,'__MONOTONIC_TIMESTAMP':'100','MESSAGE':'access ok'} for _ in range(10)]
  def encode():return b''.join((json.dumps(x)+'\n').encode() for x in rows)
  raw=encode();p={'journal_sha256':hashlib.sha256(raw).hexdigest(),'journal_entries':10,'monotonic_start_ns':99999,'monotonic_end_ns':100001}
  self.assertEqual(m.audit_journal(raw,p,boot,inv),10)
  rows[0]['MESSAGE']='database unavailable';raw=encode();p['journal_sha256']=hashlib.sha256(raw).hexdigest()
  with self.assertRaises(m.Refused):m.audit_journal(raw,p,boot,inv)
 def test_lifecycle_binds_windows_and_cleanup(self):
  pairs=[('inject','STARTING',20),('inject','PASS',30),('check','PENDING',40),('diagnosis','PASS',70),('resolve','MITIGATED',80),('check','PARTIAL',90),('reset','PASS',120)]
  events=[{'event':k,'result':v,'monotonic_ns':t} for k,v,t in pairs]
  result={'baseline':{'monotonic_end_ns':10},'fault':{'monotonic_start_ns':50,'monotonic_end_ns':60},'recovered':{'monotonic_start_ns':100,'monotonic_end_ns':110}}
  m.audit_lifecycle(events,result)
  for change in ('missing_reset','foreign_window','duplicate_inject','reordered'):
   altered=[dict(e) for e in events]; data=json.loads(json.dumps(result))
   if change=='missing_reset':altered.pop()
   if change=='foreign_window':data['fault']['monotonic_start_ns']=35
   if change=='duplicate_inject':altered.insert(2,dict(altered[1],monotonic_ns=31))
   if change=='reordered':altered[3]['monotonic_ns']=39
   with self.subTest(change=change),self.assertRaises(m.Refused):m.audit_lifecycle(altered,data)
if __name__=='__main__':unittest.main()
