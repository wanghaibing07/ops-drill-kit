import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import sys
import unittest
from unittest.mock import MagicMock,patch
if sys.platform=='win32': sys.modules.setdefault('fcntl',MagicMock())
import l02_watchdog_helper as h


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.rid='a'*24; self.inv='b'*32; self.boot='c'*36; self.sha='d'*64
        self.state={'version':1,'run_id':self.rid,'boot_id':self.boot,'phase':'REPAIRED',
                    'kind':'config-port-v1','invocation':self.inv,
                    'watchdog':{'timer':'opsdrill-l02-recover-'+self.rid+'.timer','helper_sha256':self.sha}}
        name='opsdrill-l02-'+self.rid+'.service'
        prefix='/etc/nginx/opsdrill-l02-isolated/'+self.rid+'/'
        self.props={'Id':name,'LoadState':'loaded','ActiveState':'active','Transient':'yes',
                    'FragmentPath':'/run/systemd/transient/'+name,'Type':'exec','User':'root',
                    'DropInPaths':'','InvocationID':self.inv,'ControlGroup':'/system.slice/'+name,
                    'ExecStart':'{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -p '+prefix+' -c nginx.conf -g daemon off; ; }'}

    def test_identity_requires_own_run_and_receipt(self):
        self.assertEqual(h.validate_state(self.state,self.rid,self.boot,self.sha),self.inv)
        for key,value in [('boot_id','wrong'),('kind','other'),('phase','unexpected')]:
            altered=dict(self.state); altered[key]=value
            with self.subTest(key=key),self.assertRaises(h.Refused): h.validate_state(altered,self.rid,self.boot,self.sha)
        with self.assertRaises(h.Refused): h.validate_state(self.state,self.rid,self.boot,'e'*64)

    def test_service_requires_invocation_and_exact_command(self):
        self.assertTrue(h.validate_service(self.rid,self.inv,self.props))
        for key in ('Id','InvocationID','Transient','FragmentPath','ExecStart','ControlGroup'):
            altered=dict(self.props); altered[key]='foreign'
            with self.subTest(key=key),self.assertRaises(h.Refused): h.validate_service(self.rid,self.inv,altered)
        self.assertFalse(h.validate_service(self.rid,self.inv,{'Id':self.props['Id'],'LoadState':'not-found'}))

    def test_recovery_stops_only_verified_service_and_preserves_state(self):
        after=dict(self.props,ActiveState='inactive',ControlGroup='')
        with patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
             patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
             patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=dict(self.state)), \
             patch.object(h,'properties',side_effect=[self.props,after]),patch.object(h,'command') as command, \
             patch.object(h,'save_state') as save,patch.object(h.os,'close'):
            path.return_value.read_text.return_value=self.boot
            h.recover(self.rid)
        command.assert_called_once_with('/usr/bin/systemctl','stop',self.props['Id'])
        saved=save.call_args.args[2]
        self.assertEqual(saved['phase'],'NEEDS_REVIEW')
        self.assertEqual(saved['watchdog_status'],'STOPPED_OR_ABSENT')
        self.assertIn('watchdog',saved)

    def test_refuses_changed_unit_without_stopping_or_saving(self):
        foreign=dict(self.props,InvocationID='e'*32)
        with patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
             patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
             patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=dict(self.state)), \
             patch.object(h,'properties',return_value=foreign),patch.object(h,'command') as command, \
             patch.object(h,'save_state') as save,patch.object(h.os,'close'):
            path.return_value.read_text.return_value=self.boot
            with self.assertRaises(h.Refused): h.recover(self.rid)
        command.assert_not_called(); save.assert_not_called()


if __name__=='__main__': unittest.main()
