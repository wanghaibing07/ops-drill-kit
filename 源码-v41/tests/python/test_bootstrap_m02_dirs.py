import importlib.util,os,pwd,stat,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[2]/'baseline'
spec=importlib.util.spec_from_file_location('bootstrap_m02_dirs',BASE/'bootstrap.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

@unittest.skipUnless(os.geteuid()==0,'requires root')
class BootstrapM02DirsTests(unittest.TestCase):
    def test_new_and_existing_directories(self):
        u=pwd.getpwnam('devops')
        with tempfile.TemporaryDirectory(dir=BASE.parent) as temp:
            state=Path(temp)/'state';state.mkdir(mode=0o700)
            project=Path(temp)/'project';project.mkdir();os.chown(project,u.pw_uid,u.pw_gid)
            mod.ensure_m02_dirs(state,project)
            self.assertEqual(stat.S_IMODE((state/'m02-deadlock').stat().st_mode),0o700)
            st=(project/'evidence').stat();self.assertEqual((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)),(u.pw_uid,u.pw_gid,0o755))
            mod.ensure_m02_dirs(state,project)
    def test_existing_unsafe_paths_are_not_fixed(self):
        u=pwd.getpwnam('devops')
        with tempfile.TemporaryDirectory(dir=BASE.parent) as temp:
            state=Path(temp)/'state';state.mkdir(mode=0o700)
            project=Path(temp)/'project';project.mkdir();os.chown(project,u.pw_uid,u.pw_gid)
            (project/'evidence').symlink_to(state,target_is_directory=True)
            with self.assertRaises(OSError):mod.ensure_m02_dirs(state,project)
            self.assertTrue((project/'evidence').is_symlink())

if __name__=='__main__':unittest.main()
