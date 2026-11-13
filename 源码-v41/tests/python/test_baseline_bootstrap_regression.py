"""Regression checks for the clean-install failure boundaries."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[2]/'baseline'

def load(name,path):
    import sys
    sys.path.insert(0,str(BASE))
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class BoundaryReached(RuntimeError):
    pass

@unittest.skipUnless(os.geteuid()==0,'requires root to check protected lock ownership')
class TestAdminStartPath(unittest.TestCase):
    def test_reaches_identity_loader_after_mysql_start(self):
        mod=load('baseline_admin_regression',BASE/'mysql_admin_init.py')
        with tempfile.TemporaryDirectory(prefix='opsdrill-admin-test-') as parent:
            state=Path(parent)/'state'
            with patch.object(mod.c,'STATE',state),patch.object(mod.c,'chain'),patch.object(mod,'preflight',return_value=(object(),None)),patch.object(mod,'save'),patch.object(mod,'install_config'),patch.object(mod,'run',return_value=b''),patch.object(mod.importlib.util,'spec_from_file_location',side_effect=BoundaryReached('identity loader reached')) as loader:
                with self.assertRaises(BoundaryReached):
                    mod.main(['--apply','--actor','agent'])
                self.assertEqual(loader.call_count,1)

class TestBootstrapLayout(unittest.TestCase):
    def test_repository_selection_precedes_server_install(self):
        source=(BASE/'bootstrap.py').read_text(encoding='utf8')
        self.assertLess(source.index("('mysql_repo_config',None,0)"),source.index("'mysql-community-server-8.4.13-1.el9'"))
        self.assertIn('--enablerepo=mysql-8.4-lts-community',source)
        self.assertIn('--disablerepo=mysql-9.7-lts-community',source)

if __name__=='__main__':unittest.main()
