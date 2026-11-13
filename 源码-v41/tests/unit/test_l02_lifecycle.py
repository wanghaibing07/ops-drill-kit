import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
from dataclasses import replace
from l02_lifecycle import Run, verify_fault, resolve, check, reset
from l02_selinux_ownership import MappingIntent, expected_after
from l02_policy import Refused

class Backend:
    def __init__(self):
        self.run=Run('a'*24,12345,'FAULT_PENDING','1'*8+'-'+'1'*4+'-'+'1'*4+'-'+'1'*4+'-'+'1'*12,'b'*32,42,99,'port_t')
        self.local=(); self.intent=MappingIntent(self.run.run_id,self.run.port,()); self.receipt=None
        self.lock=True; self.fail=None; self.stopped=False; self.event=None
    def load_run(self): return self.run
    def boot_id(self): return self.run.boot_id
    def guard(self): return True
    def service_identity(self,r): return True
    def pid_identity(self,r): return True
    def audit_records(self,r): return [
      'type=AVC msg=audit(100.123:7): avc: denied { name_bind } for pid=42 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:port_t:s0 tclass=tcp_socket',
      'type=SYSCALL msg=audit(100.123:7): pid=42 success=no exe="/usr/sbin/nginx"',
      'type=SOCKADDR msg=audit(100.123:7): saddr=020030397F0000010000000000000000']
    def now_seconds(self): return 101
    def save_fault_durable(self,r,event): self.run=r; self.event=event
    def watchdog_armed(self,r): return True
    def policy_lock_proven(self): return self.lock
    def mapping_intent(self,r): return self.intent
    def policy_snapshot(self): return [],self.local
    def save_intent_durable(self,r,i): self.run=r
    def add_mapping_once(self,i):
        self.local=expected_after(i)
        if self.fail=='add': raise RuntimeError('crash')
    def effective_mapping_correct(self,i,e): return True
    def save_receipt_durable(self,r,i,receipt): self.run=r; self.receipt=receipt
    def restart_owned_service(self,r): pass
    def verify_fault_record(self,r): return self.event is not None
    def mapping_receipt_valid(self,r): return self.receipt is not None
    def enforcing(self): return True
    def config_valid(self,r): return True
    def local_listener_owned(self,r): return True
    def http_health_ok(self,r): return True
    def load_receipt(self,r): return self.intent,self.receipt
    def save_remove_intent_durable(self,r): self.run=r
    def delete_mapping_once(self,i):
        self.local=i.before
        if self.fail=='delete': raise RuntimeError('crash')
    def save_restored_durable(self,r): self.run=r
    def stop_owned_service(self,r): self.stopped=True
    def verify_cleanup(self,r): return self.stopped
    def finish_durable(self,r): self.run=None
    def clean_owned_resources(self,rid): return self.stopped and self.local==()

class LifecycleTests(unittest.TestCase):
    def test_full_flow(self):
        b=Backend(); rid=b.run.run_id
        verify_fault(b,rid); resolve(b,rid); self.assertTrue(check(b,rid))
        reset(b,rid); reset(b,rid); self.assertEqual(b.local,())
    def test_crash_add_and_delete_require_manual_review(self):
        for phase in ('add','delete'):
            b=Backend(); rid=b.run.run_id; verify_fault(b,rid)
            if phase=='add':
                b.fail='add'
                with self.assertRaises(RuntimeError): resolve(b,rid)
            else:
                resolve(b,rid); b.fail='delete'
                with self.assertRaises(RuntimeError): reset(b,rid)
            with self.assertRaises(Refused): reset(b,rid)
            self.assertFalse(b.stopped)
    def test_policy_drift_and_lock_loss_fail_closed(self):
        b=Backend(); rid=b.run.run_id; verify_fault(b,rid)
        b.lock=False
        with self.assertRaises(Refused): resolve(b,rid)
        self.assertEqual(b.local,())
        b.lock=True; resolve(b,rid)
        b.local=tuple(sorted((*b.local,('udp',9999,9999,'x_t'))))
        before=b.local
        with self.assertRaises(Refused): reset(b,rid)
        self.assertEqual(b.local,before)

if __name__=='__main__': unittest.main()
