import sys as _m01_sys
from pathlib import Path as _M01Path
_m01_root=_M01Path(__file__).resolve().parents[2]
_m01_sys.path.insert(0,str(_m01_root/'drills/mysql/M01'))
import sys,types,unittest
from unittest.mock import patch
if sys.platform=='win32': sys.modules.setdefault('fcntl',types.ModuleType('fcntl'))
import m01_core as core
import m01_owned as owned


class RecoveryEdges(unittest.TestCase):
    def test_missing_watchdog_service_prevents_injection(self):
        state={'armed_ns':10}
        timer={'LoadState':'loaded','ActiveState':'active','SubState':'waiting'}
        with patch.object(owned,'units',return_value=(timer,{'LoadState':'not-found'})):
            with self.assertRaises(core.Error): owned.verify_armed(state)

    def test_timer_failure_cleans_only_verified_baseline(self):
        rid='a'*24; sha='b'*64; saved=[]
        with patch.object(core,'baseline'),patch.object(core,'read_state',return_value=None), \
             patch.object(core,'index_rows',return_value='YES'),patch.object(core,'expected_plan',return_value=core.INDEX), \
             patch.object(core,'globals_read',return_value={}),patch.object(core,'write_state',side_effect=lambda s:saved.append(s)), \
             patch.object(core,'STATE') as statefile,patch.object(core,'visibility') as ddl, \
             patch.object(owned.secrets,'token_hex',return_value=rid),patch.object(owned,'properties',return_value={'LoadState':'not-found'}), \
             patch.object(owned,'helper_digest',return_value=sha),patch.object(owned,'command',side_effect=core.Error('timer failed')), \
             patch.object(owned,'read_owned',side_effect=lambda _:saved[0]),patch.object(owned,'disarm') as disarm, \
             patch.object(owned,'Path') as path:
            path.return_value.read_text.return_value='boot'
            with self.assertRaises(core.Error): owned.start()
        disarm.assert_called_once(); statefile.unlink.assert_called_once(); ddl.assert_not_called()


if __name__=='__main__': unittest.main()
