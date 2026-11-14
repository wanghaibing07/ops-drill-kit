import contextlib,importlib.util,io,json,os,types,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
cli=load('l03_scoped_cli',ROOT/'scripts/opsdrill_cli.py');report=load('l03_scoped_report',ROOT/'scripts/report.py')
RID='a'*24;ATTEMPT='L03-20261113-123456'
def evidence():
 b={'device':'253:0','limit_device':'8:0','unit':'opsdrill-l03-'+RID+'.service','limit_bps':32000000,'disk_read_sectors':10,'cgroup_read_bytes':1,'monotonic_ns':100}
 a=dict(b,disk_read_sectors=100,cgroup_read_bytes=200,monotonic_ns=200)
 return {'before':b,'after':a}
def details():return {'run_id':RID,'l03_contract':'bounded-io-v1','io_evidence':evidence(),'elapsed_ns':9000000000,'read_bytes':268435456,'storage_read_bytes':268435456,'health_before':True,'health_after':True}
def output(d):
 return {'status':'COMPLETED','run_id':RID,'unit_active':False,'health_current':True,'bounded_io_contract':'PASS','worker':{'status':'COMPLETED','health_ok':True,'io_evidence':d['io_evidence'],'elapsed_ns':d['elapsed_ns'],'read_bytes':d['read_bytes'],'observation':{'storage_read_bytes':d['storage_read_bytes']}}}
class ScopedTests(unittest.TestCase):
 def test_success_event_contains_proof_and_historic_pass_is_not_promoted(self):
  d=details();self.assertTrue(cli.l03_details_valid(d));self.assertTrue(report.l03_details_valid(d))
  inject={'drill_id':'L03','attempt_id':ATTEMPT,'event':'inject','result':'PASS'}
  check={'drill_id':'L03','attempt_id':ATTEMPT,'event':'check','result':'PASS',**d}
  incomplete=report.summarize([json.dumps(inject),json.dumps(check)])['attempts'][0];self.assertEqual(incomplete['status'],'PARTIAL')
  reset={'drill_id':'L03','attempt_id':ATTEMPT,'event':'reset','result':'PASS'}
  incomplete=report.summarize([json.dumps(inject),json.dumps(check),json.dumps(reset)])['attempts'][0];self.assertEqual(incomplete['status'],'PARTIAL')
  clean=dict(reset,result='CLEAN');row=report.summarize([json.dumps(inject),json.dumps(check),json.dumps(reset),json.dumps(clean)])['attempts'][0]
  self.assertEqual(row['status'],'PASS');self.assertEqual(row['scope'],'bounded_io_simulation');self.assertIsNone(row['mttr_proxy_seconds'])
  legacy={k:v for k,v in check.items() if k not in d};row=report.summarize([json.dumps(inject),json.dumps(legacy)])['attempts'][0]
  self.assertNotEqual(row['status'],'PASS')
 def test_missing_or_mismatched_proof_is_partial(self):
  for mutate in ('device','limit','counter','run','health'):
   d=details()
   if mutate=='device':d['io_evidence']['after']['device']='253:1'
   if mutate=='limit':d['io_evidence']['after']['limit_bps']=0
   if mutate=='counter':d['io_evidence']['after']['cgroup_read_bytes']=1
   if mutate=='run':d['run_id']='b'*24
   if mutate=='health':d['health_after']=False
   self.assertFalse(cli.l03_details_valid(d));self.assertFalse(report.l03_details_valid(d))
 def test_cli_check_records_proof_or_partial(self):
  state={'drill_id':'L03','attempt_id':ATTEMPT,'phase':'ACTIVE','run_id':RID,'unit':'opsdrill-l03-'+RID+'.service'}
  args=types.SimpleNamespace(drill='L03',command='check',expect_run_id=RID,n04_version=None,m02_version=None)
  for valid in (True,False):
   obj=output(details())
   if not valid:obj['worker']['io_evidence']['after']['cgroup_read_bytes']=1
   proc=types.SimpleNamespace(returncode=0,stdout=json.dumps(obj),stderr='')
   with mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'),mock.patch.object(cli,'open_lock',side_effect=lambda _:os.open(os.devnull,os.O_RDONLY)),mock.patch.object(cli,'read_state',return_value=state),mock.patch.object(cli,'invoke',return_value=proc),mock.patch.object(cli,'event') as event,contextlib.redirect_stdout(io.StringIO()):
    rc=cli.action(args)
   self.assertEqual(rc,0 if valid else 2);self.assertEqual(event.call_args.args[3],'PASS' if valid else 'PARTIAL')
   if valid:self.assertTrue(cli.l03_details_valid(event.call_args.args[5]))
if __name__=='__main__':unittest.main()
