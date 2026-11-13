import sys
import unittest
from contextlib import nullcontext
from unittest.mock import MagicMock,patch
if sys.platform=='win32': sys.modules.setdefault('fcntl',MagicMock())
import l02_prepare as p
from l02_policy import Refused


class FakeJournal:
    def __init__(self): self.state=None; self.actions=[]
    def locked(self): return nullcontext()
    def read(self,rid): return self.state
    def save(self,rid,state): self.state=dict(state); self.actions.append(('save',state['phase']))
    def close(self): self.actions.append(('close',))


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.rid='a'*24; self.journal=FakeJournal()
        self.fault={'effective_listed_type':'unreserved_port_t','local_listed_type':None,'tcp_socket_present':False}
        self.good={'effective_listed_type':'http_port_t','local_listed_type':None,'tcp_socket_present':False}

    def test_prepare_persists_and_arms_before_spawning(self):
        def arm(journal,state):
            journal.actions.append(('arm',))
            updated=dict(state,watchdog={'timer':'fake'})
            journal.save(self.rid,updated)
            return updated
        def start(port,rid,before_spawn,launch_token):
            self.journal.actions.append(('start',))
            before_spawn(rid)
            self.assertEqual(self.journal.state['launch_intent'],{'version':1,'token':launch_token})
            return rid
        def initialize(journal,rid,verify):
            self.journal.actions.append(('initialize',))
            self.assertTrue(verify(rid,journal.state))
        with patch.object(p,'inspect',side_effect=[self.fault,self.good]),patch.object(p.secrets,'token_hex',side_effect=[self.rid,'e'*32]), \
             patch.object(p,'Journal',return_value=self.journal),patch.object(p,'Path') as path, \
             patch.object(p,'arm',side_effect=arm),patch.object(p,'start',side_effect=start), \
             patch.object(p,'verify_armed',return_value=True),patch.object(p,'properties',return_value={'ActiveState':'failed'}), \
             patch.object(p,'verify_unit',return_value=True),patch.object(p,'invocation_id',return_value='b'*32), \
             patch.object(p,'initialize',side_effect=initialize):
            path.return_value.read_text.return_value='boot'
            self.assertEqual(p.prepare(19081,8443),self.rid)
        self.assertEqual([x[0] for x in self.journal.actions],['save','arm','save','start','save','save','initialize','close'])
        self.assertEqual(self.journal.state['invocation'],'b'*32)

    def test_failed_arm_preserves_prepared_state_without_starting(self):
        with patch.object(p,'inspect',side_effect=[self.fault,self.good]),patch.object(p.secrets,'token_hex',return_value=self.rid), \
             patch.object(p,'Journal',return_value=self.journal),patch.object(p,'Path') as path, \
             patch.object(p,'arm',side_effect=Refused('timer failed')),patch.object(p,'start') as start:
            path.return_value.read_text.return_value='boot'
            with self.assertRaises(Refused): p.prepare(19081,8443)
        start.assert_not_called()
        self.assertEqual(self.journal.state['phase'],'PREPARED')
        self.assertEqual(self.journal.actions[-1],('close',))

    def test_busy_repair_port_refuses_before_journal(self):
        bad=dict(self.good,tcp_socket_present=True)
        with patch.object(p,'inspect',side_effect=[self.fault,bad]),patch.object(p,'Journal') as journal:
            with self.assertRaises(Refused): p.prepare(19081,8443)
        journal.assert_not_called()


if __name__=='__main__': unittest.main()
