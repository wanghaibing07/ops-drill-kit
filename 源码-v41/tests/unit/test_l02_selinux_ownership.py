import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
from l02_policy import Refused, parse_ports
from l02_selinux_ownership import canonical, digest, MappingIntent, authorize_add, expected_after, prove_after_add, authorize_delete

class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.before=canonical('SELinux Port Type Proto Port Number\nother_t udp 53\ntransproxy_port_t tcp 8081\n')
        self.intent=MappingIntent('a'*24,12345,self.before)
        self.effective=parse_ports('transproxy_port_t tcp 8081\n')
    def test_exact_add_and_delete(self):
        authorize_add(self.intent,self.effective,self.before)
        after=expected_after(self.intent)
        receipt=prove_after_add(self.intent,after,True,True)
        self.assertTrue(authorize_delete(self.intent,after,receipt,True))
    def test_existing_range_and_8081_refused(self):
        for port in (8081,12345):
            i=MappingIntent('a'*24,port,self.before)
            effective=parse_ports('transproxy_port_t tcp 8081\nother_t tcp 12000-13000\n')
            with self.assertRaises(Refused): authorize_add(i,effective,self.before)
    def test_ambiguous_crash_and_foreign_drift_refused(self):
        after=expected_after(self.intent)
        with self.assertRaises(Refused): prove_after_add(self.intent,after,False,True)
        with self.assertRaises(Refused): prove_after_add(self.intent,after,True,False)
        receipt=digest(after)
        drift=tuple(sorted((*after,('udp',9999,9999,'other_t'))))
        with self.assertRaises(Refused): authorize_delete(self.intent,drift,receipt,True)
        with self.assertRaises(Refused): authorize_delete(self.intent,after,receipt,False)
        with self.assertRaises(Refused): authorize_delete(self.intent,after,None,True)
    def test_overlap_and_bad_syntax(self):
        for text in ('one_t tcp 10-20\ntwo_t tcp 20', 'bad'):
            with self.assertRaises(Refused): canonical(text)

if __name__=='__main__': unittest.main()
