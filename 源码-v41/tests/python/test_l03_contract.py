import importlib.util,json,types,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('l03_contract',ROOT/'tests/contract/L03-partial.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
RID='a'*24;ATTEMPT='L03-20261113-123456'
def cp(rc):return types.SimpleNamespace(returncode=rc)
def items(scoped=True):
 receipt={'receipt':'L03_RUN_OWNER_V1','run_id':RID}
 observed={'status':'COMPLETED','run_id':RID,'health_current':True,'bounded_io_contract':'PASS' if scoped else 'PARTIAL'}
 reset={'status':'CLEANUP_PASS','run_id':RID}
 return [(cp(0),receipt),(cp(0 if scoped else 2),observed),(cp(0),reset)]
class ContractTests(unittest.TestCase):
 def test_scoped_success_requires_clean_report(self):
  row={'drill_id':'L03','attempt_id':ATTEMPT,'status':'PASS','scope':'bounded_io_simulation','mttr_proxy_seconds':None}
  report=types.SimpleNamespace(stdout=json.dumps({'attempts':[row]}));state=json.dumps({'run_id':RID,'phase':'ACTIVE','attempt_id':ATTEMPT})
  with mock.patch.object(m,'run',side_effect=items()),mock.patch.object(m.Path,'read_text',return_value=state),mock.patch.object(m.subprocess,'run',return_value=report):
   self.assertEqual(m.main(),0)
 def test_missing_metrics_stays_partial(self):
  state=json.dumps({'run_id':RID,'phase':'ACTIVE','attempt_id':ATTEMPT})
  with mock.patch.object(m,'run',side_effect=items(False)),mock.patch.object(m.Path,'read_text',return_value=state),mock.patch.object(m.subprocess,'run') as report:
   self.assertEqual(m.main(),2);report.assert_not_called()
 def test_bad_check_attempts_only_bound_cleanup(self):
  sequence=[items()[0],(cp(2),{'status':'FAILED'}),items()[2]];state=json.dumps({'run_id':RID,'phase':'ACTIVE','attempt_id':ATTEMPT})
  with mock.patch.object(m,'run',side_effect=sequence) as run,mock.patch.object(m.Path,'read_text',return_value=state):
   with self.assertRaises(RuntimeError):m.main()
  self.assertEqual(run.call_args_list[-1].args,('reset',RID))
if __name__=='__main__':unittest.main()
