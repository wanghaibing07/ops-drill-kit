import contextlib,importlib.util,io,json,tempfile,types,unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('cli_bounded_test',ROOT/'scripts/opsdrill_cli.py')
cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
RID='a'*24; DIGEST='b'*64

def args(**changes):
    values={'expect_run_id':RID,'evidence_dir':'/var/backups/opsdrill/C01/window-metrics-'+'c'*16,'expected_sha256':DIGEST}
    values.update(changes);return types.SimpleNamespace(**values)

class BoundedCheckTests(unittest.TestCase):
    def setUp(self):
        self.status={'status':'CLEANUP_RECORDED','run_id':RID,'same_boot':True}
        self.result={'status':'BOUNDED_OBSERVATION_PASS','run_id':RID,'result_sha256':DIGEST}
        self.read=mock.patch.object(cli,'read_state',return_value=None);self.read.start();self.addCleanup(self.read.stop)
        self.backend=mock.patch.object(cli,'c01_call',return_value=types.SimpleNamespace(returncode=0,stdout=json.dumps(self.status)));self.backend.start();self.addCleanup(self.backend.stop)
        self.run=mock.patch.object(cli.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=json.dumps(self.result)));self.run.start();self.addCleanup(self.run.stop)
    def invoke(self,a):
        with contextlib.redirect_stdout(io.StringIO()):return cli.c01_bounded_check(a)
    def test_valid_bounded_result(self):
        self.assertEqual(self.invoke(args()),0)
    def test_incomplete_or_non_agent_input_rejected(self):
        for kwargs in ({'expected_sha256':None},{'expect_run_id':None},{'expect_run_id':'wrong'}):
            with self.subTest(kwargs=kwargs),self.assertRaises(cli.Refused):self.invoke(args(**kwargs))
        cli.subprocess.run.assert_not_called()
    def test_active_or_mismatched_cleanup_rejected(self):
        cli.read_state.return_value={'phase':'ACTIVE'}
        with self.assertRaises(cli.Refused):self.invoke(args())
        cli.read_state.return_value=None
        cli.c01_call.return_value.stdout=json.dumps(dict(self.status,run_id='d'*24))
        with self.assertRaises(cli.Refused):self.invoke(args())
        cli.subprocess.run.assert_not_called()
    def test_auditor_tamper_and_result_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'audit.py';p.write_text('print(1)')
            with mock.patch.object(cli,'secure_file',return_value=p),self.assertRaises(cli.Refused):self.invoke(args())
        cli.subprocess.run.return_value.stdout=json.dumps(dict(self.result,run_id='d'*24))
        with self.assertRaises(cli.Refused):self.invoke(args())

if __name__=='__main__':unittest.main()
