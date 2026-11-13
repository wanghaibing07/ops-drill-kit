import sys as _m01_sys
from pathlib import Path as _M01Path
_m01_root=_M01Path(__file__).resolve().parents[2]
_m01_sys.path.insert(0,str(_m01_root/'drills/mysql/M01'))
_m01_sys.path.insert(0,str(_m01_root/'scripts'))
import importlib.util
import json
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest.mock import MagicMock,patch
if sys.platform=='win32': sys.modules.setdefault('fcntl',types.ModuleType('fcntl'))
source=Path(__file__).resolve().parents[2]/'scripts/m01_control.py'
spec=importlib.util.spec_from_file_location('m01_legacy',source)
legacy=importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)


class LegacyGuardTests(unittest.TestCase):
    def test_legacy_reset_rejects_cli_owned_state(self):
        path=MagicMock(); path.exists.return_value=True; path.is_symlink.return_value=False
        path.lstat.return_value=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
        path.read_text.return_value=json.dumps({'id':'M01','version':2,'globals':{}})
        with patch.object(legacy,'STATE',path):
            with self.assertRaises(legacy.Error) as result: legacy.read_state()
        self.assertEqual(result.exception.code,3)


if __name__=='__main__': unittest.main()
