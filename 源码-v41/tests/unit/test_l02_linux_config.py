import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import os
from pathlib import Path
import tempfile
import unittest
from l02_linux_config import digest,replace_config
from l02_policy import Refused
class LinuxConfigTests(unittest.TestCase):
    def test_digest_binds_exact_bytes(self):
        self.assertEqual(len(digest(b'listen 8443;')),64)
        self.assertNotEqual(digest(b'listen 8443;'),digest(b'listen 8081;'))
        self.assertNotEqual(digest(b'x'),digest(b'x\n'))

    @unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'requires root on Linux')
    def test_real_atomic_replace_and_reject_foreign_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'nginx.conf'
            path.write_bytes(b'original'); path.chmod(0o600)
            dfd=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY)
            try:
                self.assertEqual(replace_config(dfd,'nginx.conf',digest(b'original'),b'repaired'),digest(b'repaired'))
                self.assertEqual(path.read_bytes(),b'repaired')
                self.assertEqual(path.stat().st_mode & 0o777,0o600)
                with self.assertRaises(Refused): replace_config(dfd,'nginx.conf',digest(b'original'),b'other')
                self.assertEqual(path.read_bytes(),b'repaired')
            finally: os.close(dfd)

    @unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'requires root on Linux')
    def test_real_symlink_and_insecure_permissions_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'nginx.conf'; target=Path(tmp)/'target'
            target.write_bytes(b'original'); target.chmod(0o600)
            path.symlink_to(target)
            dfd=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError): replace_config(dfd,'nginx.conf',digest(b'original'),b'other')
                path.unlink(); path.write_bytes(b'original'); path.chmod(0o644)
                with self.assertRaises(Refused): replace_config(dfd,'nginx.conf',digest(b'original'),b'other')
                self.assertEqual(path.read_bytes(),b'original')
            finally: os.close(dfd)
if __name__=='__main__': unittest.main()
