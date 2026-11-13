import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
from dataclasses import replace
from l02_policy import Observation, Refused
from l02_controller import start, check, reset

A = 'a'*64
B = 'b'*64
class Fake:
    def __init__(self):
        self.state=None; self.digest=A; self.mapping=None; self.mapping_owned=False
        self.running=True; self.watchdog=False; self.fail=None; self.denial=False; self.log=[]
    def load(self): return self.state
    def no_orphans(self): return True
    def prepare_config(self,port): return A,B
    def save_durable(self,state): self.state=state; self.log.append(state.phase)
    def arm_watchdog(self,state): self.watchdog=True
    def observe(self,state): return Observation(True,True,True,self.digest,True,True,self.mapping,self.watchdog)
    def install_fault_config_if_original(self,state):
        if self.digest != state.original_digest: raise Refused('config changed')
        self.digest=state.fault_digest
        if self.fail=='after-config': raise RuntimeError('interrupted')
    def verify_fault_prerequisites(self,state):
        if self.mapping is not None: raise Refused('policy changed')
    def restart_owned_service(self,state): self.running=False
    def observe_expected_denial(self,state): self.denial=True; return True
    def verify_injection_evidence(self,state): return self.denial
    def recovery_observation(self,state): return (200 if self.running else 503,self.running,self.running,True)
    def reset_observation(self,state): return self.digest,self.mapping,self.mapping_owned,None,self.running
    def restore_config_if_fault(self,state):
        if self.digest != state.fault_digest: raise Refused('changed')
        self.digest=state.original_digest
        if self.fail=='after-restore': raise RuntimeError('interrupted')
    def remove_owned_mapping_if_unchanged(self,state):
        if self.mapping != 'http_port_t' or not self.mapping_owned: raise Refused('foreign')
        self.mapping=None
    def recover_owned_service(self,state): self.running=True
    def verify_baseline(self,state): return self.digest==A and self.mapping is None and self.running
    def cancel_owned_watchdog(self,state): self.watchdog=False
    def verify_cleanup(self,state): return not self.watchdog
    def finish_durable(self,state): self.state=None
    def clean_and_healthy(self): return self.state is None and self.digest==A and self.mapping is None and self.running and not self.watchdog
    def record_failure(self,state): self.log.append('failure')

class ControllerTests(unittest.TestCase):
    def test_full_recovery_and_idempotence(self):
        b=Fake(); rid=start(b,12345)
        self.assertFalse(check(b,rid))
        b.mapping='http_port_t'; b.mapping_owned=True; b.running=True
        self.assertTrue(check(b,rid))
        reset(b,rid); reset(b,rid)
        self.assertTrue(b.clean_and_healthy())
    def test_partial_injection_recoverable(self):
        b=Fake(); b.fail='after-config'
        with self.assertRaises(RuntimeError): start(b,12345)
        self.assertEqual(b.state.phase,'CONFIG_REQUESTED')
        self.assertTrue(b.watchdog)
        b.fail=None; reset(b,b.state.run_id)
        self.assertTrue(b.clean_and_healthy())
    def test_interrupted_reset_retry(self):
        b=Fake(); rid=start(b,12345); b.fail='after-restore'
        with self.assertRaises(RuntimeError): reset(b,rid)
        self.assertEqual(b.state.phase,'RESETTING')
        b.fail=None; reset(b,rid); self.assertTrue(b.clean_and_healthy())
    def test_foreign_mapping_and_config_untouched(self):
        for resource in ('config','mapping'):
            b=Fake(); rid=start(b,12345)
            if resource=='config': b.digest='c'*64
            else: b.mapping='http_port_t'; b.mapping_owned=False
            before=(b.digest,b.mapping,b.running)
            with self.assertRaises(Refused): reset(b,rid)
            self.assertEqual(before,(b.digest,b.mapping,b.running))
            self.assertTrue(b.watchdog)
    def test_injection_preflight_existing_mapping_rejected(self):
        b=Fake(); b.mapping='transproxy_port_t'
        with self.assertRaises(Refused): start(b,8081)
        self.assertEqual(b.digest,A); self.assertIsNotNone(b.state)
    def test_wrong_run_cannot_check_or_reset(self):
        b=Fake(); rid=start(b,12345)
        with self.assertRaises(Refused): check(b,'0'*24)
        with self.assertRaises(Refused): reset(b,'0'*24)
        self.assertEqual(b.state.run_id,rid)

if __name__=='__main__': unittest.main()
