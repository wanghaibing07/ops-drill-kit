import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
from l02_audit import verify_denial
from l02_policy import Refused

class AuditTests(unittest.TestCase):
    def records(self):
        return [
          'type=AVC msg=audit(100.123:7): avc: denied { name_bind } for pid=42 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:port_t:s0 tclass=tcp_socket',
          'type=SYSCALL msg=audit(100.123:7): pid=42 success=no exe="/usr/sbin/nginx"',
          'type=SOCKADDR msg=audit(100.123:7): saddr=020030397F0000010000000000000000']
    def check(self,rows): return verify_denial(rows,min_seconds=99,max_seconds=101,pid=42,executable='/usr/sbin/nginx',port=12345,expected_target_type='port_t')
    def test_success_returns_only_identity(self): self.assertEqual(self.check(self.records())['audit_serial'],'7')
    def test_requires_same_serial_address_and_pid(self):
        original=self.records()
        variants=[original[:2], original[:2]+[original[2].replace(':7)',':8)')],
                  original[:2]+[original[2].replace('7F000001','00000000')],
                  [original[0],original[1].replace('pid=42','pid=43'),original[2]]]
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaises(Refused): self.check(rows)
    def test_duplicate_matching_events_refused(self):
        rows=self.records(); rows += [x.replace(':7)',':8)') for x in rows]
        with self.assertRaises(Refused): self.check(rows)
    def test_wrong_context_refused(self):
        rows=self.records(); rows[0]=rows[0].replace(':port_t:',':http_port_t:')
        with self.assertRaises(Refused): self.check(rows)

if __name__=='__main__': unittest.main()
