import importlib.util,os,stat,tempfile,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('bootstrap_n03_dropin',ROOT/'baseline/bootstrap.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

@unittest.skipUnless(os.geteuid()==0,'requires root-controlled parent')
class N03DropinTests(unittest.TestCase):
 def test_preflight_is_read_only_and_apply_is_idempotent(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as name:
   parent=Path(name);directory=parent/'orderguard-api.service.d';target=directory/'40-opsdrill-n03.conf'
   self.assertEqual(m.inspect_n03_slow_dropin(parent),'create-directory-and-file');self.assertFalse(directory.exists())
   m.ensure_n03_slow_dropin(parent);self.assertEqual(target.read_bytes(),m.N03_SLOW_DROPIN)
   st=target.stat();self.assertEqual(st.st_uid,0);self.assertEqual(stat.S_IMODE(st.st_mode),0o644)
   sentinel=directory/'unrelated.conf';sentinel.write_text('preserve');before=target.stat().st_ino
   self.assertEqual(m.inspect_n03_slow_dropin(parent),'same');m.ensure_n03_slow_dropin(parent)
   self.assertEqual(target.stat().st_ino,before);self.assertEqual(sentinel.read_text(),'preserve')
 def test_conflicting_file_is_not_overwritten(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as name:
   parent=Path(name);directory=parent/'orderguard-api.service.d';directory.mkdir();target=directory/'40-opsdrill-n03.conf';target.write_text('user configuration')
   with self.assertRaises(m.Refusal):m.ensure_n03_slow_dropin(parent)
   self.assertEqual(target.read_text(),'user configuration')
 def test_symlinks_and_writable_parent_rejected(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as name:
   parent=Path(name);(parent/'orderguard-api.service.d').symlink_to(parent,target_is_directory=True)
   with self.assertRaises((m.Refusal,OSError)):m.ensure_n03_slow_dropin(parent)
  with tempfile.TemporaryDirectory(dir=ROOT) as name:
   parent=Path(name);directory=parent/'orderguard-api.service.d';directory.mkdir();(directory/'40-opsdrill-n03.conf').symlink_to(parent/'other')
   with self.assertRaises((m.Refusal,OSError)):m.ensure_n03_slow_dropin(parent)
  with tempfile.TemporaryDirectory(dir=ROOT) as name:
   parent=Path(name);directory=parent/'orderguard-api.service.d';directory.mkdir();directory.chmod(0o777)
   with self.assertRaises(m.Refusal):m.ensure_n03_slow_dropin(parent)

if __name__=='__main__':unittest.main()
