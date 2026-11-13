import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
from l02_linux_inspect import listening_tcp
from l02_policy import Refused

class LinuxInspectTests(unittest.TestCase):
    def test_ipv4_ipv6_and_non_listening_are_occupied(self):
        header='  sl  local_address rem_address   st\n'
        v4=header+'0: 0100007F:1F91 00000000:0000 0A\n'
        v6=header+'0: 00000000000000000000000000000000:3039 00000000000000000000000000000000:0000 06\n'
        self.assertTrue(listening_tcp(8081,[v4,header]))
        self.assertTrue(listening_tcp(12345,[header,v6]))
        self.assertFalse(listening_tcp(12346,[v4,v6]))
    def test_bad_table_refused(self):
        with self.assertRaises(Refused): listening_tcp(12345,['invalid'])
        with self.assertRaises(Refused): listening_tcp(12345,['local_address\n broken'])

if __name__ == '__main__': unittest.main()
