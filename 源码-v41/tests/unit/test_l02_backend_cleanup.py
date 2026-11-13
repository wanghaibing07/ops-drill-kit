import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock,patch
if sys.platform=='win32': sys.modules.setdefault('fcntl',MagicMock())
from l02_config_lifecycle import ConfigRun
from l02_linux_config_backend import LinuxConfigBackend
from l02_policy import Refused


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'requires root on Linux')
class BackendCleanupTests(unittest.TestCase):
    def prepare(self,root):
        rid='a'*24; directory=Path(root)/rid; directory.mkdir(mode=0o700)
        original=b'good-config'; fault=b'fault-config'
        state=ConfigRun(rid,19081,8443,'RESTORED',hashlib.sha256(original).hexdigest(),
                        hashlib.sha256(fault).hexdigest(),hashlib.sha256(original).hexdigest())
        (directory/'nginx.conf').write_bytes(original)
        (directory/'state.json').write_text(json.dumps({'run_id':rid,'port':19081,'sha256':state.fault_sha}))
        for name in ('nginx.conf','state.json'): (directory/name).chmod(0o600)
        backend=object.__new__(LinuxConfigBackend); backend.run_id=rid; backend.record={'phase':'RESTORED'}
        backend.journal=MagicMock(); backend.verify_cleanup=lambda _: True
        @contextmanager
        def locked():
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        return backend,state,directory,locked

    def test_removes_only_exact_owned_run(self):
        with tempfile.TemporaryDirectory() as root:
            backend,state,directory,locked=self.prepare(root)
            with patch('l02_linux_config_backend.locked',locked): backend.finish(state)
            self.assertFalse(directory.exists())
            backend.journal.remove.assert_called_once_with(state.run_id,{'phase':'RESTORED'})

    def test_extra_file_refuses_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            backend,state,directory,locked=self.prepare(root)
            (directory/'foreign').write_bytes(b'x')
            with patch('l02_linux_config_backend.locked',locked),self.assertRaises(Refused): backend.finish(state)
            self.assertTrue((directory/'nginx.conf').exists())
            backend.journal.remove.assert_not_called()


if __name__=='__main__': unittest.main()
