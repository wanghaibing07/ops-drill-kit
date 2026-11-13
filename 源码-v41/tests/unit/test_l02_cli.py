import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import contextlib
import io
import json
import subprocess
import sys
import unittest
from unittest.mock import MagicMock,patch
if sys.platform=='win32': sys.modules.setdefault('fcntl',MagicMock())
import l02_cli
import l02_prepare
from l02_policy import Refused


class CliTests(unittest.TestCase):
    def test_start_outputs_bound_receipt(self):
        rid='a'*24; out=io.StringIO()
        with patch.object(l02_cli,'guard'),patch.object(l02_prepare,'prepare',return_value=rid),contextlib.redirect_stdout(out):
            self.assertEqual(l02_cli.main(['start','19081','8443']),0)
        self.assertEqual(json.loads(out.getvalue()),{'receipt':'L02_CONFIG_OWNER_V1','run_id':rid,
                                                    'timer':'opsdrill-l02-recover-'+rid+'.timer'})

    def test_verify_owner_requires_fault_evidence_and_timer(self):
        rid='b'*24; backend=MagicMock()
        backend.journal.locked.return_value=contextlib.nullcontext()
        backend.load.return_value=MagicMock(phase='FAULT')
        backend.watchdog_armed.return_value=True; backend.fault_present.return_value=True
        with patch.object(l02_cli,'guard'),patch.object(l02_cli,'LinuxConfigBackend',return_value=backend):
            self.assertEqual(l02_cli.main(['verify-owner',rid]),0)
            backend.fault_present.return_value=False
            with self.assertRaises(Refused): l02_cli.main(['verify-owner',rid])

    def test_clean_inspection_refuses_remaining_units(self):
        with patch.object(l02_cli.os.path,'lexists',return_value=False), \
             patch.object(l02_cli,'command',return_value=subprocess.CompletedProcess([],0,'foreign.service loaded active\n','')):
            with self.assertRaises(Refused): l02_cli.inspect_clean()


if __name__=='__main__': unittest.main()
