import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import install_l02 as installer


class InstallerTests(unittest.TestCase):
    def test_reviewed_manifest_matches_sources(self):
        root=Path(__file__).resolve().parents[2]/'drills/linux/L02'
        self.assertGreaterEqual(len(installer.MANIFEST),10)
        if any(not (root/name).exists() for name in installer.MANIFEST):
            self.skipTest('partial isolated test bundle')
        for name,digest in installer.MANIFEST.items():
            self.assertEqual(hashlib.sha256((root/name).read_text(encoding='utf-8').encode()).hexdigest(),digest)

    @unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'requires root on Linux')
    def test_install_is_idempotent_and_refuses_foreign_modules(self):
        with tempfile.TemporaryDirectory() as root:
            data={'l02_a.py':b'one','l02_b.py':b'two'}
            manifest={name:hashlib.sha256(content).hexdigest() for name,content in data.items()}
            with patch.object(installer,'MANIFEST',manifest):
                self.assertEqual(installer.install(data,root),2)
                self.assertEqual(installer.install(data,root),0)
                target=Path(root)/'usr/local/libexec/opsdrill/l02'
                (target/'l02_a.py').write_bytes(b'foreign')
                with self.assertRaises(installer.Refused): installer.install(data,root)
                self.assertEqual((target/'l02_a.py').read_bytes(),b'foreign')

    @unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'requires root on Linux')
    def test_unknown_file_prevents_install(self):
        with tempfile.TemporaryDirectory() as root:
            target=Path(root)/'usr/local/libexec/opsdrill/l02'; target.mkdir(parents=True)
            (target/'foreign.py').write_bytes(b'x')
            with patch.object(installer,'MANIFEST',{'l02_a.py':hashlib.sha256(b'one').hexdigest()}):
                with self.assertRaises(installer.Refused): installer.install({'l02_a.py':b'one'},root)
            self.assertFalse((target/'l02_a.py').exists())


if __name__=='__main__': unittest.main()
