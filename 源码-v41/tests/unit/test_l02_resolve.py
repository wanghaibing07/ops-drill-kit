import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import unittest
from types import SimpleNamespace
from l02_policy import Refused
from l02_selinux_ownership import MappingIntent, expected_after
from l02_resolve import resolve

class B:
    def __init__(self):
        self.state=SimpleNamespace(run_id='a'*24,port=12345,phase='FAULT',validate=lambda:None)
        self.intent=MappingIntent(self.state.run_id,self.state.port,())
        self.local=(); self.lock=True; self.log=[]; self.crash=False
    def policy_transaction_lock_proven(self): return self.lock
    def load_run(self): return self.state
    def verify_watchdog(self,s): return True
    def verify_owned_service(self,s): return True
    def verify_injection_evidence(self,s): return True
    def make_mapping_intent(self,s): return self.intent
    def policy_snapshot(self): return ([],self.local)
    def save_mapping_intent_durable(self,s,i): self.log.append('intent')
    def add_http_port_once(self,s,i):
        self.log.append('add'); self.local=expected_after(i)
        if self.crash: raise RuntimeError('crash')
    def effective_is_exact_owned_http(self,e,i): return True
    def save_mapping_receipt_durable(self,s,i,r): self.log.append('receipt')
    def restart_owned_service(self,s): self.log.append('restart')
    def verify_recovery(self,s): return True

class ResolveTests(unittest.TestCase):
    def test_order(self):
        b=B(); resolve(b,b.state.run_id)
        self.assertEqual(b.log,['intent','add','receipt','restart'])
    def test_no_proven_global_lock_no_mutation(self):
        b=B(); b.lock=False
        with self.assertRaises(Refused): resolve(b,b.state.run_id)
        self.assertEqual(b.log,[])
    def test_crash_leaves_intent_without_receipt(self):
        b=B(); b.crash=True
        with self.assertRaises(RuntimeError): resolve(b,b.state.run_id)
        self.assertEqual(b.log,['intent','add'])

if __name__=='__main__': unittest.main()
