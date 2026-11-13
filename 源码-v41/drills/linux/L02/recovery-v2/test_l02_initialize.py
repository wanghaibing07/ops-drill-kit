import sys,unittest
from unittest.mock import MagicMock,patch
if sys.platform=='win32': sys.modules.setdefault('fcntl',MagicMock())
from l02_policy import Refused
from l02_initialize import initialize
from l02_isolated import config_for
import hashlib,json

class Journal:
    def __init__(self,row): self.row=row; self.saved=None
    def read(self,rid): return self.row
    def save(self,rid,row): self.saved=row

class InitTests(unittest.TestCase):
    def test_initialize_needs_authenticated_watchdog(self):
        rid='a'*24; good=hashlib.sha256(config_for(rid,8443)).hexdigest(); fault=hashlib.sha256(config_for(rid,12345)).hexdigest()
        boot='1'*8+'-'+'1'*4+'-'+'1'*4+'-'+'1'*4+'-'+'1'*12
        record={'version':1,'run_id':rid,'phase':'PREPARED','kind':'config-port-v1','boot_id':boot,'started_epoch':100,'invocation':'b'*32,
                'config_run':{'run_id':rid,'fault_port':12345,'good_port':8443,'phase':'FAULT',
                              'original_sha':good,'fault_sha':fault,'fixed_sha':good}}
        j=Journal(record)
        with patch('l02_initialize.Path') as p, patch('l02_initialize.time.time',return_value=101), \
             patch('l02_initialize.properties',return_value={}),patch('l02_initialize.verify_unit',return_value=True), \
             patch('l02_initialize.invocation_id',return_value='b'*32):
            p.return_value.read_text.return_value=boot
            with self.assertRaises(Refused): initialize(j,rid,lambda rid,state:False)
            self.assertIsNone(j.saved)
            with patch('l02_initialize.run_checked',side_effect=['{}\n','','unreserved_port_t tcp 1024-32767\n']), \
                 patch('l02_initialize.correlate',return_value={'audit':{'audit_serial':'7'}}):
                proof=initialize(j,rid,lambda rid,state:True)
                self.assertEqual(proof['audit']['audit_serial'],'7')
                self.assertEqual(j.saved['phase'],'FAULT')
                self.assertEqual(j.saved['fault_proof'],proof)


    def test_initialize_refuses_changed_invocation(self):
        rid='a'*24; good=hashlib.sha256(config_for(rid,8443)).hexdigest(); fault=hashlib.sha256(config_for(rid,12345)).hexdigest()
        boot='boot'
        record={'version':1,'run_id':rid,'phase':'PREPARED','kind':'config-port-v1','boot_id':boot,'started_epoch':100,
                'invocation':'b'*32,'launch_intent':{'version':1,'token':'e'*32},
                'config_run':{'run_id':rid,'fault_port':12345,'good_port':8443,'phase':'FAULT',
                              'original_sha':good,'fault_sha':fault,'fixed_sha':good}}
        j=Journal(record)
        with patch('l02_initialize.Path') as p, patch('l02_initialize.time.time',return_value=101), \
             patch('l02_initialize.properties',return_value={}),patch('l02_initialize.verify_unit',return_value=True) as verify, \
             patch('l02_initialize.invocation_id',return_value='c'*32),patch('l02_initialize.run_checked') as collect:
            p.return_value.read_text.return_value=boot
            with self.assertRaises(Refused): initialize(j,rid,lambda rid,state:True)
            verify.assert_called_once_with(rid,{},'e'*32)
            collect.assert_not_called(); self.assertIsNone(j.saved)

if __name__=='__main__': unittest.main()
