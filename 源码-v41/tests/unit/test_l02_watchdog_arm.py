import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import sys
import subprocess
import unittest
from unittest.mock import MagicMock,patch
if sys.platform=='win32': sys.modules.setdefault('fcntl',MagicMock())
import l02_watchdog_arm as a
from l02_policy import Refused


class WatchdogArmTests(unittest.TestCase):
    def setUp(self):
        self.rid='a'*24; self.sha='b'*64
        self.timer='opsdrill-l02-recover-'+self.rid+'.timer'
        self.state={'version':1,'phase':'PREPARED','kind':'config-port-v1','run_id':self.rid,'boot_id':'boot'}
        self.armed=dict(self.state,watchdog={'timer':self.timer,'helper_sha256':self.sha,'armed_ns':100})
        service=self.timer[:-6]+'.service'
        self.timer_props={'Id':self.timer,'LoadState':'loaded','ActiveState':'active','SubState':'waiting',
                          'Triggers':service,'Transient':'yes','FragmentPath':'/run/systemd/transient/'+self.timer}
        self.service_props={'Id':service,'LoadState':'loaded','Transient':'yes',
                            'FragmentPath':'/run/systemd/transient/'+service,'User':'root',
                            'ExecStart':'{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I '+str(a.HELPER)+' '+self.rid+' ; }'}

    def test_timer_and_helper_identity_are_required(self):
        with patch.object(a,'helper_digest',return_value=self.sha),patch.object(a,'properties',side_effect=[self.timer_props,self.service_props]),patch.object(a.time,'monotonic_ns',return_value=101):
            self.assertTrue(a.verify_armed(self.armed))
        changed=dict(self.service_props,ExecStart='foreign')
        with patch.object(a,'helper_digest',return_value=self.sha),patch.object(a,'properties',side_effect=[self.timer_props,changed]),patch.object(a.time,'monotonic_ns',return_value=101):
            with self.assertRaises(Refused): a.verify_armed(self.armed)

    def test_receipt_persisted_before_timer_start(self):
        order=[]; journal=MagicMock(); journal.save.side_effect=lambda *args: order.append('save')
        def command(*args,**kw):
            if args[0]=='/usr/bin/systemd-detect-virt': return subprocess.CompletedProcess(args,0,'vmware\n','')
            if args[0]=='/usr/sbin/getenforce': return subprocess.CompletedProcess(args,0,'Enforcing\n','')
            order.append('systemd-run'); return subprocess.CompletedProcess(args,0,'','')
        with patch.object(a.os,'geteuid',return_value=0,create=True),patch.object(a,'secure_marker'), \
             patch.object(a,'Path') as path,patch.object(a,'properties',return_value={'LoadState':'not-found'}), \
             patch.object(a,'helper_digest',return_value=self.sha),patch.object(a,'command',side_effect=command), \
             patch.object(a,'verify_armed',return_value=True),patch.object(a.time,'monotonic_ns',return_value=100):
            path.return_value.read_text.return_value='boot'
            state=a.arm(journal,self.state)
        self.assertEqual(order,['save','systemd-run'])
        self.assertEqual(state['watchdog']['timer'],self.timer)

    def test_existing_unit_prevents_arming(self):
        journal=MagicMock()
        def command(*args,**kw):
            return subprocess.CompletedProcess(args,0,'vmware\n' if args[0].endswith('systemd-detect-virt') else 'Enforcing\n','')
        with patch.object(a.os,'geteuid',return_value=0,create=True),patch.object(a,'secure_marker'), \
             patch.object(a,'Path') as path,patch.object(a,'properties',return_value={'LoadState':'loaded'}), \
             patch.object(a,'command',side_effect=command):
            path.return_value.read_text.return_value='boot'
            with self.assertRaises(Refused): a.arm(journal,self.state)
        journal.save.assert_not_called()

    def test_cancel_stops_only_own_timer(self):
        service=dict(self.service_props,ActiveState='inactive')
        with patch.object(a,'helper_digest',return_value=self.sha), \
             patch.object(a,'properties',side_effect=[self.timer_props,service,{'LoadState':'not-found'}]), \
             patch.object(a,'command') as command:
            self.assertTrue(a.cancel_owned(self.armed))
        command.assert_called_once_with('/usr/bin/systemctl','stop',self.timer)

    def test_cancel_refuses_running_helper_and_foreign_timer(self):
        service=dict(self.service_props,ActiveState='active')
        with patch.object(a,'helper_digest',return_value=self.sha), \
             patch.object(a,'properties',side_effect=[self.timer_props,service]), \
             patch.object(a,'command') as command:
            with self.assertRaises(Refused): a.cancel_owned(self.armed)
        command.assert_not_called()
        service['ActiveState']='inactive'; timer=dict(self.timer_props,Transient='no')
        with patch.object(a,'helper_digest',return_value=self.sha), \
             patch.object(a,'properties',side_effect=[timer,service]), \
             patch.object(a,'command') as command:
            with self.assertRaises(Refused): a.cancel_owned(self.armed)
        command.assert_not_called()


if __name__=='__main__': unittest.main()
