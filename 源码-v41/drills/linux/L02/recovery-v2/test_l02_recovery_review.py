import sys
import unittest
from unittest.mock import MagicMock, patch
if sys.platform == 'win32': sys.modules.setdefault('fcntl', MagicMock())
import l02_watchdog_helper as h

class RecoveryReviewTests(unittest.TestCase):
    def setUp(self):
        self.rid='a'*24; self.inv='b'*32; self.sha='d'*64; self.boot='boot'; self.token='e'*32
        unit='opsdrill-l02-'+self.rid+'.service'
        self.state={'version':1,'run_id':self.rid,'boot_id':self.boot,'phase':'NEEDS_REVIEW',
                    'kind':'config-port-v1','invocation':self.inv,
                    'launch_intent':{'version':1,'token':self.token},
                    'watchdog':{'timer':'opsdrill-l02-recover-'+self.rid+'.timer','helper_sha256':self.sha}}
        self.props={'Id':unit,'LoadState':'loaded','ActiveState':'inactive','Transient':'yes',
                    'FragmentPath':'/run/systemd/transient/'+unit,'Type':'exec','User':'root','DropInPaths':'',
                    'InvocationID':self.inv,'ControlGroup':'', 'Description':'opsdrill-l02-launch-'+self.rid+'-'+self.token,
                    'Restart':'no','NRestarts':'0','RuntimeMaxUSec':'2min',
                    'ExecStart':'{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -p /etc/nginx/opsdrill-l02-isolated/'+self.rid+'/ -c nginx.conf -g daemon off; ; }'}

    def recover(self,state,props):
        with patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
             patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
             patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=state), \
             patch.object(h,'properties',return_value=props),patch.object(h,'command') as command, \
             patch.object(h,'save_state') as save,patch.object(h.os,'close'):
            path.return_value.read_text.return_value=self.boot
            with self.assertRaises(h.Refused): h.recover(self.rid)
            command.assert_not_called(); save.assert_not_called()

    def test_recorded_invocation_still_requires_launch_marker(self):
        self.recover(dict(self.state),dict(self.props,Description='foreign'))

    def test_missing_cgroup_empty_proof_is_not_success(self):
        self.recover(dict(self.state),dict(self.props,ControlGroup='/system.slice/'+self.props['Id']))

    def test_invalid_launch_intent_is_not_ignored(self):
        self.recover(dict(self.state,launch_intent={'version':1,'token':'bad'}),self.props)

    def test_null_invocation_is_rejected(self):
        with self.assertRaises(h.Refused):
            h.validate_state(dict(self.state,invocation='0'*32),self.rid,self.boot,self.sha)

if __name__=='__main__': unittest.main()
