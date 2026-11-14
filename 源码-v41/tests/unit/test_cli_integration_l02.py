import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

path=Path(__file__).resolve().parents[2]/'scripts/opsdrill_cli.py'
spec=importlib.util.spec_from_file_location('cli_candidate_l02',path)
cli=importlib.util.module_from_spec(spec)
with patch.dict(sys.modules,{'fcntl':types.ModuleType('fcntl')}): spec.loader.exec_module(cli)
RID='a'*24


class IntegrationTests(unittest.TestCase):
    def args(self,command):
        return argparse.Namespace(command=command,drill='L02',variant=None,expect_run_id=None)

    def test_start_validates_timer_receipt_and_owner(self):
        receipt={'receipt':'L02_CONFIG_OWNER_V1','run_id':RID,'timer':'opsdrill-l02-recover-'+RID+'.timer'}
        cp=subprocess.CompletedProcess([],0,json.dumps(receipt),''); written=[]
        with patch.object(cli,'require_root'),patch.object(cli,'safe_dir'),patch.object(cli,'open_lock',return_value=3), \
             patch.object(cli.os,'close'),patch.object(cli,'read_state',return_value=None),patch.object(cli,'script_path'), \
             patch.object(cli,'allocate_id',return_value='L02-20261112-123456'),patch.object(cli,'event'), \
             patch.object(cli,'write_state',side_effect=lambda _,s:written.append(dict(s))), \
             patch.object(cli,'invoke',return_value=cp),patch.object(cli,'l02_command',return_value=['verified']), \
             patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            self.assertEqual(cli.action(self.args('start')),0)
        self.assertEqual(written[-1]['phase'],'ACTIVE')
        self.assertEqual(written[-1]['run_id'],RID)
        self.assertEqual(written[-1]['timer'],receipt['timer'])

    def test_confirmed_fault_is_pending_and_reset_uses_run_id(self):
        state={'drill_id':'L02','attempt_id':'L02-20261112-123456','phase':'ACTIVE',
               'run_id':RID,'timer':'opsdrill-l02-recover-'+RID+'.timer'}
        def invoke(drill,action,extra=(),capture=False,l02_version='legacy'):
            if capture: return subprocess.CompletedProcess([],1,'L02 fault confirmed\n','')
            return 0
        with patch.object(cli,'require_root'),patch.object(cli,'safe_dir'),patch.object(cli,'open_lock',return_value=3), \
             patch.object(cli.os,'close'),patch.object(cli,'read_state',return_value=state), \
             patch.object(cli,'event') as event,patch.object(cli.os,'unlink'),patch.object(cli,'invoke',side_effect=invoke) as call:
            self.assertEqual(cli.action(self.args('check')),1)
            self.assertEqual(event.call_args.args[3],'PENDING')
            self.assertEqual(cli.action(self.args('reset')),0)
            call.assert_called_with('L02','reset',(RID,),l02_version='legacy')

    def test_clean_repeat_reset_requires_clean_inspection(self):
        with patch.object(cli,'require_root'),patch.object(cli,'safe_dir'),patch.object(cli,'open_lock',return_value=3), \
             patch.object(cli.os,'close'),patch.object(cli,'read_state',return_value=None),patch.object(cli,'l02_clean',return_value=3):
            with self.assertRaises(cli.Refused): cli.action(self.args('reset'))


if __name__=='__main__': unittest.main()
