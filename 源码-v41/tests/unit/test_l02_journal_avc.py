import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
from l02_journal_avc import correlate
from l02_policy import Refused

class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.rid='a'*24; self.boot='b'*32; self.inv='c'*32
        self.row={'_SYSTEMD_UNIT':'opsdrill-l02-'+self.rid+'.service','_BOOT_ID':self.boot,
                  '_SYSTEMD_INVOCATION_ID':self.inv,'_EXE':'/usr/sbin/nginx','_PID':'42',
                  '__REALTIME_TIMESTAMP':'100100000', 'MESSAGE':'nginx: bind() to 127.0.0.1:12345 failed (13: Permission denied)'}
        self.audit=['type=AVC msg=audit(100.123:7): avc: denied { name_bind } for pid=42 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:port_t:s0 tclass=tcp_socket',
                    'type=SYSCALL msg=audit(100.123:7): pid=42 success=no exe="/usr/sbin/nginx"',
                    'type=SOCKADDR msg=audit(100.123:7): saddr=020030397F0000010000000000000000']
    def call(self,rows,audit=None):
        return correlate(rows,audit or self.audit,run_id=self.rid,boot_id=self.boot,invocation=self.inv,port=12345,started_epoch=99,ended_epoch=103)
    def test_correlates_without_live_process(self):
        x=self.call([self.row]); self.assertEqual(x['pid'],42); self.assertEqual(x['audit']['audit_serial'],'7')
        self.assertNotIn('MESSAGE',x)
    def test_mismatch_fails(self):
        for key in ('_SYSTEMD_UNIT','_BOOT_ID','_SYSTEMD_INVOCATION_ID','_EXE','_PID','MESSAGE','__REALTIME_TIMESTAMP'):
            row=dict(self.row); row[key]='wrong'
            with self.subTest(key=key),self.assertRaises(Refused): self.call([row])
    def test_ambiguous_and_unrelated_avc_fail(self):
        with self.assertRaises(Refused): self.call([self.row,self.row])
        changed=[s.replace('pid=42','pid=43') for s in self.audit]
        with self.assertRaises(Refused): self.call([self.row],changed)
        changed=[s.replace('(100.123:7)','(200.123:7)') for s in self.audit]
        with self.assertRaises(Refused): self.call([self.row],changed)
    def test_no_sockaddr_can_use_explicit_journal_port_evidence(self):
        audit=self.audit[:2]
        audit[1]=audit[1].replace('pid=42','arch=c000003e syscall=49 pid=42')
        row=dict(self.row); row.pop('_EXE')
        args=dict(run_id=self.rid,boot_id=self.boot,invocation=self.inv,port=12345,started_epoch=99,ended_epoch=103)
        with self.assertRaises(Refused): correlate([row],audit,**args)
        proof=correlate([row],audit,allow_journal_port=True,**args)
        self.assertEqual(proof['audit']['address_source'],'journal_message')
        with self.assertRaises(Refused):
            correlate([row],[audit[0],audit[1].replace('syscall=49','syscall=42')],allow_journal_port=True,**args)
        wrong=dict(row); wrong['MESSAGE']='bind() to 127.0.0.1:12346 failed (13: Permission denied)'
        with self.assertRaises(Refused): correlate([wrong],audit,allow_journal_port=True,**args)
        with self.assertRaises(Refused): correlate([row,row],audit,allow_journal_port=True,**args)

if __name__=='__main__': unittest.main()
