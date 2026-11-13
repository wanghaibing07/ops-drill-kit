import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import sys,unittest
from unittest.mock import MagicMock,patch
from types import SimpleNamespace
if sys.platform=='win32': sys.modules.setdefault('fcntl',MagicMock())
from l02_linux_config_backend import LinuxConfigBackend
from l02_policy import Refused

class BackendTests(unittest.TestCase):
    def test_live_safety_gates_are_disabled_without_evidence(self):
        b=object.__new__(LinuxConfigBackend)
        self.assertFalse(b.watchdog_armed(None))
        b.record={}
        state=SimpleNamespace(run_id='a'*24,fault_port=12345)
        self.assertFalse(b.verify_fault_evidence(state))
        b.service_identity=lambda _: False
        self.assertFalse(b.health(state,8443))
        self.assertFalse(b.verify_restored(None))
        with self.assertRaises(Refused): b.cancel_owned_watchdog(None)

    def test_restart_saves_new_invocation_under_journal_lock(self):
        b=object.__new__(LinuxConfigBackend); b.run_id='a'*24
        b.record={'invocation':'b'*32}; b.journal=MagicMock(); b.service_identity=lambda _:True
        state=SimpleNamespace(run_id=b.run_id)
        with patch('l02_linux_config_backend.invocation_id',side_effect=['b'*32,'c'*32]), \
             patch('l02_linux_config_backend.command') as command:
            b.restart_owned_service(state)
        command.assert_called_once_with('/usr/bin/systemctl','restart','opsdrill-l02-'+b.run_id+'.service')
        self.assertEqual(b.record['invocation'],'c'*32)
        self.assertEqual(b.journal.save.call_args.args[1]['invocation'],'c'*32)

    def test_restart_refuses_unowned_invocation(self):
        b=object.__new__(LinuxConfigBackend); b.run_id='a'*24
        b.record={'invocation':'b'*32}; b.journal=MagicMock(); b.service_identity=lambda _:True
        with patch('l02_linux_config_backend.invocation_id',return_value='c'*32), \
             patch('l02_linux_config_backend.command') as command:
            with self.assertRaises(Refused): b.restart_owned_service(SimpleNamespace(run_id=b.run_id))
        command.assert_not_called(); b.journal.save.assert_not_called()

if __name__=='__main__': unittest.main()
