import contextlib,importlib.util,io,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('bootstrap_n03_wiring',ROOT/'baseline/bootstrap.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

@unittest.skipUnless(os.geteuid()==0,'requires root-controlled temporary parent')
class N03BootstrapWiringTests(unittest.TestCase):
 def case(self,conflict):
  with tempfile.TemporaryDirectory(dir=ROOT) as temp:
   root=Path(temp);systemd=root/'systemd';systemd.mkdir();target=systemd/'orderguard-api.service.d'/'40-opsdrill-n03.conf'
   if conflict:target.parent.mkdir();target.write_text('preserve')
   state=root/'bootstrap-state';journal=state/'run.json';calls=[];actual=m.ensure_n03_slow_dropin
   def run(args,timeout=120):
    if any('orchestrate.py' in str(x) for x in args):self.assertEqual(target.read_bytes(),m.N03_SLOW_DROPIN)
    calls.append(args);return b''
   with patch.object(m,'STATE',state),patch.object(m,'JOURNAL',journal),patch.object(m,'preflight'),patch.object(m,'create_marker'),patch.object(m,'ensure_lab_dirs'),patch.object(m,'ensure_contract_evidence_dirs'),patch.object(m,'ensure_m02_dirs'),patch.object(m,'configure_mysql_repo'),patch.object(m,'install_m04'),patch.object(m,'ensure_n03_slow_dropin',side_effect=lambda:actual(systemd)),patch.object(m,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
    code=m.main(['--vm-uuid','11111111-2222-3333-4444-555555555555','--apply','--actor','agent'])
   record=json.loads(journal.read_text())
   if conflict:
    self.assertEqual(code,2);self.assertEqual(record['phase'],'n03_slow_dropin');self.assertEqual(target.read_text(),'preserve')
    self.assertFalse(any('orchestrate.py' in str(x) for cmd in calls for x in cmd))
   else:
    self.assertEqual((code,record['status'],record['actor']),(0,'DONE','agent'))
    self.assertTrue(any('orchestrate.py' in str(x) for cmd in calls for x in cmd))
 def test_installs_before_stack_start(self):self.case(False)
 def test_conflict_preserved_and_stack_not_started(self):self.case(True)

if __name__=='__main__':unittest.main()
