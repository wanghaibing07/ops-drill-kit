"""Installer regression tests: preserve the separately implemented triage60 files."""
import importlib.util
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

FILE=Path(__file__).resolve().parents[2]/'scripts/install_l03.py'
spec=importlib.util.spec_from_file_location('install_l03',str(FILE))
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)

class InstallerTests(unittest.TestCase):
    def make_archive(self, path, extra=None):
        with zipfile.ZipFile(path,'w') as z:
            for name in sorted(installer.ALLOWED):
                z.writestr(name,('package:'+name+'\n').encode())
            for name,data in (extra or {}).items():
                z.writestr(name,data)

    def test_triage60_files_are_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'lib').mkdir(); (root/'lib/guard.sh').write_text('# guard\n')
            protected={
                'scripts/triage60.py':'triage python sentinel\n',
                'scripts/triage60.sh':'triage shell sentinel\n',
                'tests/unit/test_triage60.py':'triage tests sentinel\n',
            }
            for name,data in protected.items():
                dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(data)
            archive=root/'package.zip';self.make_archive(archive)
            old=os.getcwd()
            try:
                os.chdir(root)
                with patch.object(installer,'PROJECT',root):
                    installer.main(['install_l03.py',str(archive)])
            finally: os.chdir(old)
            for name,data in protected.items():
                self.assertEqual((root/name).read_text(),data)

    def test_package_cannot_include_triage60_files(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'lib').mkdir(); (root/'lib/guard.sh').write_text('# guard\n')
            archive=root/'package.zip'
            self.make_archive(archive,{'scripts/triage60.py':b'overwrite attempt'})
            old=os.getcwd()
            try:
                os.chdir(root)
                with patch.object(installer,'PROJECT',root):
                    with self.assertRaisesRegex(SystemExit,'PROTECTED_USER_FILE_IN_PACKAGE'):
                        installer.main(['install_l03.py',str(archive)])
            finally: os.chdir(old)
            self.assertFalse((root/'scripts/triage60.py').exists())

    def test_modified_l03_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'lib').mkdir(); (root/'lib/guard.sh').write_text('# guard\n')
            target=root/'drills/linux/L03/inject.sh';target.parent.mkdir(parents=True);target.write_text('user edit\n')
            archive=root/'package.zip';self.make_archive(archive)
            old=os.getcwd()
            try:
                os.chdir(root)
                with patch.object(installer,'PROJECT',root):
                    with self.assertRaisesRegex(SystemExit,'REFUSE_OVERWRITE'):
                        installer.main(['install_l03.py',str(archive)])
            finally: os.chdir(old)
            self.assertEqual(target.read_text(),'user edit\n')

if __name__=='__main__': unittest.main()
