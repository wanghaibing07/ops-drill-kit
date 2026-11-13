import sys as _m01_sys
from pathlib import Path as _M01Path
_m01_root=_M01Path(__file__).resolve().parents[2]
_m01_sys.path.insert(0,str(_m01_root/'drills/mysql/M01'))
_m01_sys.path.insert(0,str(_m01_root/'scripts'))
import json
import sys
import types
import unittest
from unittest.mock import patch
if sys.platform=='win32': sys.modules.setdefault('fcntl',types.ModuleType('fcntl'))
import m01_core as core
import m01_owned as owned
import m01_watchdog as watchdog


class M01OwnedTests(unittest.TestCase):
    def setUp(self):
        self.rid='a'*24; self.sha='b'*64
        self.state={'id':'M01','version':2,'run_id':self.rid,'globals':{'local_infile':'0'},
                    'timer':'opsdrill-m01-recover-'+self.rid+'.timer','helper_sha256':self.sha,
                    'armed_ns':10,'boot_id':'boot'}

    def test_start_arms_watchdog_before_index_change(self):
        order=[]
        with patch.object(core,'baseline'),patch.object(core,'read_state',return_value=None), \
             patch.object(core,'index_rows',side_effect=['YES','NO']), \
             patch.object(core,'expected_plan',side_effect=[core.INDEX,'other']), \
             patch.object(core,'globals_read',return_value={'local_infile':'0'}), \
             patch.object(core,'write_state',side_effect=lambda _:order.append('state')), \
             patch.object(core,'visibility',side_effect=lambda _:order.append('ddl')), \
             patch.object(owned.secrets,'token_hex',return_value=self.rid), \
             patch.object(owned,'properties',return_value={'LoadState':'not-found'}), \
             patch.object(owned,'helper_digest',return_value=self.sha), \
             patch.object(owned,'command',side_effect=lambda *args:order.append('timer')), \
             patch.object(owned,'verify_armed',side_effect=lambda _:order.append('verify')), \
             patch.object(owned,'Path') as path,patch.object(owned.time,'monotonic_ns',return_value=10):
            path.return_value.read_text.return_value='boot'
            owned.start()
        self.assertEqual(order,['state','timer','verify','ddl'])

    def test_failed_timer_never_changes_index(self):
        with patch.object(core,'baseline'),patch.object(core,'read_state',return_value=None), \
             patch.object(core,'index_rows',return_value='YES'),patch.object(core,'expected_plan',return_value=core.INDEX), \
             patch.object(core,'globals_read',return_value={}),patch.object(core,'write_state') as save, \
             patch.object(core,'visibility') as ddl,patch.object(owned.secrets,'token_hex',return_value=self.rid), \
             patch.object(owned,'properties',return_value={'LoadState':'not-found'}), \
             patch.object(owned,'helper_digest',return_value=self.sha), \
             patch.object(owned,'command',side_effect=core.Error('timer failed')),patch.object(owned,'Path') as path:
            path.return_value.read_text.return_value='boot'
            with self.assertRaises(core.Error): owned.start()
        save.assert_called_once(); ddl.assert_not_called()

    def test_wrong_run_and_running_watchdog_refuse(self):
        with patch.object(core,'read_state',return_value=self.state),patch.object(owned,'helper_digest',return_value=self.sha), \
             patch.object(owned,'Path') as path:
            path.return_value.read_text.return_value='boot'
            with self.assertRaises(core.Error): owned.read_owned('c'*24)
        with patch.object(owned,'units',return_value=({'LoadState':'loaded'},{'LoadState':'loaded','ActiveState':'active'})), \
             patch.object(owned,'command') as command:
            with self.assertRaises(core.Error): owned.disarm(self.state)
        command.assert_not_called()

    def test_watchdog_validates_exact_index_definition(self):
        rows='1\tmerchant_id\tNO\n2\torder_status\tNO\n3\tcreated_at\tNO'
        with patch.object(watchdog,'sql',return_value=rows): self.assertEqual(watchdog.index_visibility(),'NO')
        with patch.object(watchdog,'sql',return_value=rows.replace('created_at','other')):
            with self.assertRaises(watchdog.Refused): watchdog.index_visibility()

    def test_reboot_reset_requires_old_timer_to_be_absent(self):
        with patch.object(core,'read_state',return_value=self.state),patch.object(owned,'helper_digest',return_value=self.sha), \
             patch.object(owned,'Path') as path,patch.object(owned,'units',return_value=({'LoadState':'not-found'},{'LoadState':'not-found'})):
            path.return_value.read_text.return_value='new-boot'
            with self.assertRaises(core.Error): owned.read_owned(self.rid)
            self.assertEqual(owned.read_owned(self.rid,allow_reboot=True),self.state)
        with patch.object(core,'read_state',return_value=self.state),patch.object(owned,'helper_digest',return_value=self.sha), \
             patch.object(owned,'Path') as path,patch.object(owned,'units',return_value=({'LoadState':'loaded'},{'LoadState':'not-found'})):
            path.return_value.read_text.return_value='new-boot'
            with self.assertRaises(core.Error): owned.read_owned(self.rid,allow_reboot=True)

    def test_stale_watchdog_cannot_adopt_new_run(self):
        with patch.object(watchdog,'secure_file',return_value=json.dumps(self.state).encode()):
            self.assertIsNone(watchdog.read_owned('c'*24,self.sha,'boot'))


if __name__=='__main__': unittest.main()
