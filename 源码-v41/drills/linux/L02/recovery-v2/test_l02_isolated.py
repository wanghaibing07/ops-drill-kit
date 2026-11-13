import unittest
import sys
from contextlib import nullcontext
from unittest.mock import MagicMock,patch
if sys.platform == "win32": sys.modules.setdefault("fcntl", MagicMock())
from l02_isolated import config_for, verify_unit, expected_exec
import l02_isolated as isolated
from l02_policy import Refused

class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.rid='a'*24; unit='opsdrill-l02-'+self.rid+'.service'
        self.props={'Id':unit,'LoadState':'loaded','FragmentPath':'/run/systemd/transient/'+unit,
                    'Type':'exec','User':'root','DropInPaths':'','RuntimeMaxUSec':'2min','ControlGroup':'/system.slice/'+unit,
                    'ExecStart':'{ path=/usr/sbin/nginx ; argv[]='+expected_exec(self.rid)+' ; ignore_errors=no ; }'}
    def test_exact_unit_identity(self):
        self.assertTrue(verify_unit(self.rid,self.props))
        for field in ('Id','FragmentPath','ExecStart','ControlGroup','Type'):
            p=dict(self.props); p[field]='foreign'
            with self.subTest(field=field), self.assertRaises(Refused): verify_unit(self.rid,p)
        self.assertFalse(verify_unit(self.rid,{'LoadState':'not-found'}))
    def test_config_is_isolated_and_validates_inputs(self):
        data=config_for(self.rid,12345)
        self.assertIn(b'listen 127.0.0.1:12345;',data)
        self.assertIn(('pid /run/opsdrill-l02-'+self.rid+'.pid;').encode(),data)
        self.assertNotIn(b'include /etc/nginx',data)
        with self.assertRaises(Refused): config_for('../bad',12345)
        with self.assertRaises(Refused): config_for(self.rid,80)

    def test_prewrite_marker_is_in_start_command(self):
        token='e'*32; sequence=[]
        info={'effective_listed_type':'unreserved_port_t','local_listed_type':None,'tcp_socket_present':False}
        def command(*args,**kwargs): sequence.append(args)
        def before(rid): sequence.append(('intent',rid))
        with patch.object(isolated,'inspect',return_value=info), patch.object(isolated,'locked',return_value=nullcontext(7)), \
             patch.object(isolated.os,'mkdir'),patch.object(isolated.os,'fsync'),patch.object(isolated.os,'close'), \
             patch.object(isolated,'run_fd',return_value=8),patch.object(isolated,'write_new'), \
             patch.object(isolated,'properties',return_value={}),patch.object(isolated,'verify_unit',side_effect=[False,True]), \
             patch.object(isolated,'command',side_effect=command):
            isolated.start(19081,rid=self.rid,before_spawn=before,launch_token=token)
        launch=next(x for x in sequence if x[0]=='/usr/bin/systemd-run')
        self.assertIn('--property=Description=opsdrill-l02-launch-'+self.rid+'-'+token,launch)
        self.assertLess(sequence.index(('intent',self.rid)),sequence.index(launch))

    def test_marker_mismatch_refuses(self):
        token='e'*32
        with self.assertRaises(Refused): verify_unit(self.rid,self.props,token)
        props=dict(self.props,Description='opsdrill-l02-launch-'+self.rid+'-'+token)
        self.assertTrue(verify_unit(self.rid,props,token))

if __name__=='__main__': unittest.main()
