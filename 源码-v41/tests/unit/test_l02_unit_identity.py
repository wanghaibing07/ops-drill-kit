import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
from l02_policy import Refused
from l02_unit_identity import validate_unit

class UnitTests(unittest.TestCase):
    def test_requires_exact_unit_and_command(self):
        rid='a'*24; prefix='/etc/nginx/opsdrill-l02-isolated/'+rid+'/'; path=prefix+'nginx.conf'
        name='opsdrill-l02-'+rid+'.service'
        p={'Id':name,'LoadState':'loaded','FragmentPath':'/run/systemd/transient/'+name,'Type':'exec','User':'root','DropInPaths':'','ControlGroup':'/system.slice/'+name,'InvocationID':'b'*32}
        argv=['/usr/sbin/nginx','-p',prefix,'-c','nginx.conf','-g','daemon off;']
        self.assertEqual(validate_unit(rid,p,argv,path),'b'*32)
        for field in ('Id','FragmentPath','ControlGroup','InvocationID'):
            bad=dict(p); bad[field]='wrong'
            with self.subTest(field=field), self.assertRaises(Refused): validate_unit(rid,bad,argv,path)
        with self.assertRaises(Refused): validate_unit(rid,p,argv+['-q'],path)

if __name__=='__main__': unittest.main()
