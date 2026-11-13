import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
from l02_policy import Refused,parse_ports
from l02_config_lifecycle import ConfigRun, repair,check,reset

class Fake:
    def __init__(self):
        self.s=ConfigRun('a'*24,12345,8443,'FAULT','a'*64,'b'*64,'c'*64)
        self.digest='b'*64; self.policy=(parse_ports('http_port_t tcp 8443\n'),[])
        self.available=True; self.evidence=True; self.running=False; self.fail=None; self.watch=True
    def load(self): return self.s
    def guard(self): return True
    def same_boot(self,s): return True
    def service_identity(self,s): return True
    def verify_fault_evidence(self,s): return self.evidence
    def watchdog_armed(self,s): return self.watch
    def port_snapshots(self): return self.policy
    def port_available(self,p): return self.available
    def config_digest(self,s): return self.digest
    def save(self,s): self.s=s
    def replace_owned_config(self,s,old,new):
        if self.digest!=old: raise Refused('changed')
        self.digest=new
        if self.fail=='replace': raise RuntimeError('crash')
    def restart_owned_service(self,s): self.running=True
    def health(self,s,p): return self.running
    def stop_owned_service(self,s): self.running=False
    def verify_restored(self,s): return self.digest==s.original_sha and not self.running
    def cancel_owned_watchdog(self,s): self.watch=False
    def verify_cleanup(self,s): return not self.watch
    def finish(self,s): self.s=None
    def clean(self,r): return self.s is None and self.digest=='a'*64 and not self.running

class LifecycleTest(unittest.TestCase):
    def test_no_policy_mutation_and_repeat_reset(self):
        b=Fake(); rid=b.s.run_id; policy=b.policy
        repair(b,rid); self.assertTrue(check(b,rid)); reset(b,rid); reset(b,rid)
        self.assertEqual(b.policy,policy)
    def test_repair_crash_and_recover(self):
        b=Fake(); rid=b.s.run_id; b.fail='replace'
        with self.assertRaises(RuntimeError): repair(b,rid)
        self.assertEqual(b.s.phase,'REPAIR_INTENT'); b.fail=None; reset(b,rid)
        self.assertTrue(b.clean(rid))
    def test_foreign_configuration_refused(self):
        b=Fake(); rid=b.s.run_id; b.digest='d'*64
        with self.assertRaises(Refused): reset(b,rid)
        self.assertEqual(b.digest,'d'*64)
    def test_invalid_port_and_missing_avc_refused(self):
        for mutate in ('port','avc','busy'):
            b=Fake(); rid=b.s.run_id
            if mutate=='port': b.policy=(parse_ports('transproxy_port_t tcp 8443\n'),[])
            if mutate=='avc': b.evidence=False
            if mutate=='busy': b.available=False
            with self.subTest(mutate=mutate), self.assertRaises(Refused): repair(b,rid)
            self.assertEqual(b.digest,'b'*64)

if __name__=='__main__': unittest.main()
