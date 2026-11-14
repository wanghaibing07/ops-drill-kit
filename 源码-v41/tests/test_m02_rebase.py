import importlib.util
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

try:
    import fcntl
except ImportError:
    sys.modules.setdefault('fcntl',types.ModuleType('fcntl'))
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rebased_cli',ROOT/'scripts/opsdrill_cli.py')
cli=importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
RID='a'*24
OTHER='b'*24

class DispatchTests(unittest.TestCase):
    def setUp(self):
        for patch in (mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'),
                      mock.patch.object(cli,'open_lock',return_value=123),mock.patch.object(cli.os,'close'),
                      mock.patch.object(cli,'m02_action',return_value=12),
                      mock.patch.object(cli,'m03_action',return_value=13)):
            patch.start(); self.addCleanup(patch.stop)
    def run_action(self,drill,command,rid,state):
        args=SimpleNamespace(drill=drill,command=command,expect_run_id=rid,n04_version=None,variant=None)
        with mock.patch.object(cli,'read_state',return_value=state): return cli.action(args)
    def test_m03_start_and_owned_operations_remain_dispatched(self):
        self.assertEqual(self.run_action('M03','start',None,None),13)
        state={'phase':'ACTIVE','run_id':RID}
        for command in ('check','resolve','reset'):
            self.assertEqual(self.run_action('M03',command,RID,state),13)
        self.assertEqual(cli.m03_action.call_count,4)
        cli.m02_action.assert_not_called()
    def test_m03_still_rejects_missing_and_wrong_id(self):
        state={'phase':'ACTIVE','run_id':RID}
        for command in ('check','resolve','reset'):
            for requested in (None,OTHER):
                with self.assertRaises(cli.Refused): self.run_action('M03',command,requested,state)
        cli.m03_action.assert_not_called()
    def test_only_m02_check_without_cli_state_reaches_handler(self):
        self.assertEqual(self.run_action('M02','check',RID,None),12)
        self.assertEqual(self.run_action('M02','reset',RID,None),12)
        for drill in ('M03','N04','L04'):
            with self.assertRaises(cli.Refused): self.run_action(drill,'check',RID,None)
        self.assertEqual(cli.m02_action.call_count,2)
    def test_m02_wrong_id_is_rejected_before_dispatch(self):
        state={'phase':'ACTIVE','run_id':RID}
        for command in ('check','reset'):
            with self.assertRaises(cli.Refused): self.run_action('M02',command,OTHER,state)
        cli.m02_action.assert_not_called()
    def test_cli_parser_preserves_m03_and_accepts_m02_id(self):
        with mock.patch.object(cli,'action',return_value=0) as action:
            self.assertEqual(cli.main(['check','M02','--expect-run-id',RID]),0)
            self.assertEqual(action.call_args.args[0].expect_run_id,RID)
            self.assertEqual(cli.main(['reset','M03','--expect-run-id',RID]),0)
            self.assertEqual(action.call_args.args[0].drill,'M03')

if __name__=='__main__': unittest.main()
