import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
from l02_policy import Observation, Refused, parse_ports, port_type, preflight, recovered, reset_decision

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.ok = Observation(True, True, True, 'a'*64, True, True, None, True)

    def test_mapping_and_ranges(self):
        rows = parse_ports('SELinux Port Type  Proto Port Number\nhttp_port_t tcp 80, 443, 8000-8001\ntransproxy_port_t tcp 8081\nother udp 8082\n')
        self.assertEqual(port_type(rows, 8081), 'transproxy_port_t')
        self.assertEqual(port_type(rows, 8001), 'http_port_t')
        self.assertIsNone(port_type(rows, 8082))

    def test_unknown_listing_and_overlap_fail_closed(self):
        for s in ('http_port_t tcp unknown', 'a tcp 1,,2'):
            with self.subTest(s=s), self.assertRaises(Refused): parse_ports(s)
        with self.assertRaises(Refused): port_type(parse_ports('a tcp 1024-1025\nb tcp 1025-1026'),1025)

    def test_generic_overlap_and_sctp_are_handled(self):
        rows=parse_ports('unreserved_port_t tcp 1024-32767\nhttp_port_t tcp 8443\nother sctp 8443\n')
        self.assertEqual(port_type(rows,8443),'http_port_t')
        self.assertEqual(port_type(rows,19081),'unreserved_port_t')

    def test_preflight_rejects_existing_mapping_and_missing_watchdog(self):
        preflight(self.ok)
        for changes in ({'tcp_policy':'transproxy_port_t'}, {'watchdog_armed':False}, {'enforcing':False}, {'port_available':False}):
            with self.subTest(changes=changes), self.assertRaises(Refused):
                preflight(Observation(**(self.ok.__dict__ | changes)))

    def test_check_needs_real_independent_observations(self):
        o = Observation(**(self.ok.__dict__ | {'tcp_policy':'http_port_t'}))
        self.assertTrue(recovered(o, 'a'*64, 200, True, True, True))
        for args in [(500,True,True,True),(200,False,True,True),(200,True,False,True),(200,True,True,False)]:
            self.assertFalse(recovered(o, 'a'*64, *args))
        self.assertFalse(recovered(o, 'b'*64, 200, True, True, True))

    def test_reset_ownership_and_idempotence(self):
        self.assertEqual(reset_decision('fault','orig','fault','http_port_t',True,None,False), ['restore_owned_config','remove_owned_mapping','verify_or_recover_owned_service'])
        self.assertEqual(reset_decision('orig','orig','fault',None,False,None,True), [])
        with self.assertRaises(Refused): reset_decision('other','orig','fault',None,False,None,True)
        with self.assertRaises(Refused): reset_decision('orig','orig','fault','http_port_t',False,None,True)
        with self.assertRaises(Refused): reset_decision('orig','orig','fault','transproxy_port_t',True,None,True)

if __name__ == '__main__': unittest.main()
