import sys as _m01_sys
from pathlib import Path as _M01Path
_m01_root=_M01Path(__file__).resolve().parents[2]
_m01_sys.path.insert(0,str(_m01_root/'drills/mysql/M01'))
_m01_sys.path.insert(0,str(_m01_root/'scripts'))
import argparse,importlib.util,json
from pathlib import Path
import subprocess,sys,types,unittest
from unittest.mock import patch
path=Path(__file__).resolve().parents[2]/'scripts/opsdrill_cli.py'
spec=importlib.util.spec_from_file_location('cli_m01_candidate',path)
cli=importlib.util.module_from_spec(spec)
with patch.dict(sys.modules,{'fcntl':types.ModuleType('fcntl')}): spec.loader.exec_module(cli)
RID='a'*24


class CliM01Tests(unittest.TestCase):
    def args(self,action): return argparse.Namespace(command=action,drill='M01',actor='agent',variant=None,expect_run_id=None)

    def test_start_validates_owner_and_records_timer(self):
        receipt={'receipt':'M01_INDEX_OWNER_V1','run_id':RID,'timer':'opsdrill-m01-recover-'+RID+'.timer'}
        cp=subprocess.CompletedProcess([],0,json.dumps(receipt),''); written=[]
        with patch.object(cli,'require_root'),patch.object(cli,'safe_dir'),patch.object(cli,'open_lock',return_value=3), \
             patch.object(cli.os,'close'),patch.object(cli,'read_state',return_value=None),patch.object(cli,'script_path'), \
             patch.object(cli,'allocate_id',return_value='M01-20261112-123456'),patch.object(cli,'event'), \
             patch.object(cli,'write_state',side_effect=lambda _,s:written.append(dict(s))), \
             patch.object(cli,'invoke',return_value=cp),patch.object(cli,'m01_command',return_value=['verified']), \
             patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            self.assertEqual(cli.action(self.args('start')),0)
        self.assertEqual(written[-1]['phase'],'ACTIVE'); self.assertEqual(written[-1]['timer'],receipt['timer'])

    def test_confirmed_fault_is_pending_and_reset_is_bound(self):
        state={'drill_id':'M01','attempt_id':'M01-20261112-123456','phase':'ACTIVE','run_id':RID,
               'timer':'opsdrill-m01-recover-'+RID+'.timer'}
        def invoke(drill,action,extra=(),capture=False):
            if capture: return subprocess.CompletedProcess([],1,'FAIL: M01 injected, target index invisible; plan uses other\n','')
            return 0
        with patch.object(cli,'require_root'),patch.object(cli,'safe_dir'),patch.object(cli,'open_lock',return_value=3), \
             patch.object(cli.os,'close'),patch.object(cli,'read_state',return_value=state), \
             patch.object(cli,'event') as event,patch.object(cli.os,'unlink'),patch.object(cli,'invoke',side_effect=invoke) as call:
            self.assertEqual(cli.action(self.args('check')),1); self.assertEqual(event.call_args.args[3],'PENDING')
            self.assertEqual(cli.action(self.args('reset')),0); call.assert_called_with('M01','reset',(RID,))


if __name__=='__main__': unittest.main()
