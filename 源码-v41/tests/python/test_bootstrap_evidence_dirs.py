import importlib.util,os,stat,tempfile,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('bootstrap_evidence_dirs',ROOT/'baseline/bootstrap.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

@unittest.skipUnless(os.geteuid()==0,'requires root-controlled parent')
class EvidenceDirsTests(unittest.TestCase):
 def test_creates_all_without_modifying_existing(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as name:
   parent=Path(name);m.ensure_contract_evidence_dirs(parent)
   base=parent/'backups/opsdrill'
   for drill in ('M02','M03','M04','C01'):
    st=(base/drill).lstat();self.assertEqual(st.st_uid,0);self.assertEqual(stat.S_IMODE(st.st_mode),0o700)
   marker=base/'M04'/'preserve';marker.write_text('keep');m.ensure_contract_evidence_dirs(parent);self.assertEqual(marker.read_text(),'keep')
 def test_symlink_and_writable_existing_directory_are_refused(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as name:
   parent=Path(name);(parent/'backups').symlink_to(parent,target_is_directory=True)
   with self.assertRaises(m.Refusal):m.ensure_contract_evidence_dirs(parent)
  with tempfile.TemporaryDirectory(dir=ROOT) as name:
   parent=Path(name);d=parent/'backups';d.mkdir();os.chmod(d,0o777)
   with self.assertRaises(m.Refusal):m.ensure_contract_evidence_dirs(parent)
   self.assertEqual(stat.S_IMODE(d.stat().st_mode),0o777)

if __name__=='__main__':unittest.main()
