import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
import sys
from unittest.mock import MagicMock
if sys.platform == "win32": sys.modules.setdefault("fcntl", MagicMock())
from l02_isolated import config_for, verify_unit, expected_exec
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

if __name__=='__main__': unittest.main()
