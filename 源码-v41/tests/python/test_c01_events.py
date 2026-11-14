import contextlib
import copy
import importlib.util
import io
import json
import stat
from pathlib import Path
import types
import unittest
from unittest import mock
from test_c01_integration_candidate import m as controller_module, cli, MemoryStore, BOOT

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('local_report', ROOT/'scripts/report.py')
report=importlib.util.module_from_spec(spec);spec.loader.exec_module(report)
RID='a'*24
ATTEMPT='C01-20261113-123456'

def args(command,rid=None,kind=None):
    return types.SimpleNamespace(drill='C01',command=command,expect_run_id=rid,variant=None,n04_version=None,kind=kind)

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.cli_state=None;self.logs=[];self.store=MemoryStore();self.fault=True
        self.backend=mock.Mock();self.backend.call.side_effect=self.backend_call
        self.controller=controller_module.Controller(self.store,self.backend,lambda:BOOT)
        fakeos=types.SimpleNamespace(close=lambda fd:None,unlink=self.unlink,open=lambda *a:99,fsync=lambda fd:None,O_RDONLY=0,O_DIRECTORY=0,O_NOFOLLOW=0,O_CLOEXEC=0,fstat=lambda fd:types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0))
        patches=[mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'),
                 mock.patch.object(cli,'open_lock',return_value=9),mock.patch.object(cli,'os',fakeos),
                 mock.patch.object(cli,'read_state',side_effect=lambda drill:copy.deepcopy(self.cli_state)),
                 mock.patch.object(cli,'write_state',side_effect=lambda drill,state:setattr(self,'cli_state',copy.deepcopy(state))),
                 mock.patch.object(cli,'allocate_id',return_value=ATTEMPT),mock.patch.object(cli,'c01_event',side_effect=lambda rid,*a:self.logs.append(('C01',*a))),
                 mock.patch.object(cli.secrets,'token_hex',side_effect=lambda n:RID if n==12 else 'b'*32),
                 mock.patch.object(cli,'c01_call',side_effect=self.call)]
        for p in patches:p.start();self.addCleanup(p.stop)
    def unlink(self,path): self.cli_state=None
    def backend_call(self,action,receipt):
        if action=='inject':return 0,receipt
        if action=='check': return (1,{}) if self.fault else (0,{})
        return 0,{}
    def call(self,action,expected=None,capture=False):
        rc,obj=self.controller.execute(action,expected)
        return types.SimpleNamespace(returncode=rc,stdout=json.dumps(obj),stderr='')
    def invoke(self,command,rid=None,kind=None):
        with contextlib.redirect_stdout(io.StringIO()):return cli.action(args(command,rid,kind))
    def test_lifecycle_records_partial_not_pass_and_report(self):
        self.assertEqual(self.invoke('start'),0)
        self.assertEqual(self.cli_state['run_id'],RID)
        self.assertEqual(self.store.record['receipt']['run_id'],RID)
        hint=mock.Mock();hint.stat.return_value.st_size=4;hint.read_text.return_value='hint'
        with mock.patch.object(cli,'secure_file',return_value=hint):self.assertEqual(self.invoke('hint'),0)
        self.assertEqual(self.invoke('note',kind='diagnosis'),0)
        self.assertEqual(self.invoke('check',RID),1)
        self.assertEqual(self.invoke('resolve',RID),0)
        self.fault=False
        self.assertEqual(self.invoke('check',RID),2)
        self.assertEqual(self.cli_state['last_check'],'RECOVERED_PARTIAL')
        self.assertEqual(self.invoke('reset',RID),0)
        self.assertIsNone(self.cli_state);self.assertTrue(self.store.done)
        self.assertEqual([(x[2],x[3]) for x in self.logs], [('inject','STARTING'),('inject','PASS'),('hint','PASS'),('diagnosis','PASS'),('check','PENDING'),('resolve','MITIGATED'),('check','PARTIAL'),('reset','PASS')])
        lines=[json.dumps({'drill_id':d,'attempt_id':a,'run_id':RID,'event':k,'result':r}) for d,a,k,r,*_ in self.logs]
        result=report.summarize(lines); self.assertEqual(result['invalid_lines'],0)
        self.assertEqual(result['attempts'][0]['status'],'PARTIAL')
        self.assertIsNone(result['attempts'][0]['mttr_proxy_seconds'])
    def test_start_interruption_retains_bound_identity_and_no_pass_event(self):
        self.backend.call.side_effect=RuntimeError('interrupted after receipt')
        with self.assertRaises(RuntimeError):self.invoke('start')
        self.assertEqual(self.store.record['receipt']['run_id'],RID)
        self.assertEqual((self.cli_state['run_id'],self.cli_state['phase']),(RID,'NEEDS_RESET'))
        self.assertEqual([(x[2],x[3]) for x in self.logs],[('inject','STARTING')])
        with self.assertRaises(cli.Refused):self.invoke('check',RID)
        self.backend.call.side_effect=self.backend_call
        self.assertEqual(self.invoke('reset',RID),0)
        self.assertTrue(self.store.done)
    def test_no_event_write_prevents_backend(self):
        cli.c01_event.side_effect=OSError('fsync failed')
        with self.assertRaises(OSError):self.invoke('start')
        self.backend.call.assert_not_called()
        self.assertEqual((self.cli_state['run_id'],self.cli_state['phase']),(RID,'STARTING'))
    def test_legacy_run_is_not_adopted_or_given_events(self):
        receipt={'kind':'C01_APP_DOWN_V1','run_id':RID,'owner_id':'b'*32,'timer':'opsdrill-n03-recover-'+RID+'.timer'}
        self.store.record={'version':1,'receipt':receipt,'boot_id':BOOT}
        self.fault=False
        self.assertEqual(self.invoke('check',RID),2)
        self.assertEqual(self.invoke('reset',RID),0)
        self.assertEqual(self.logs,[]);self.assertIsNone(self.cli_state)
    def test_existing_unfinished_legacy_receipt_refuses_start_without_events(self):
        receipt={'kind':'C01_APP_DOWN_V1','run_id':'c'*24,'owner_id':'b'*32,'timer':'opsdrill-n03-recover-'+'c'*24+'.timer'}
        self.store.record={'version':1,'receipt':receipt,'boot_id':BOOT}
        with self.assertRaisesRegex(cli.Refused,'existing or unverified'):self.invoke('start')
        self.assertIsNone(self.cli_state);self.assertEqual(self.logs,[])
        self.backend.call.assert_not_called()

    def test_failed_check_is_not_partial(self):
        self.invoke('start')
        cli.c01_call.side_effect=lambda *args,**kwargs:types.SimpleNamespace(returncode=2,stdout='{"status":"FAIL_CLOSED"}',stderr='')
        with self.assertRaisesRegex(cli.Refused,'check unconfirmed'):self.invoke('check',RID)
        self.assertNotIn(('check','PARTIAL'),[(x[2],x[3]) for x in self.logs])

    def test_timeout_after_receipt_retains_run_and_does_not_claim_fault(self):
        import subprocess
        def timed_out(action,expected=None,capture=False):
            if action=='status':return self.call(action,expected,capture)
            self.controller.execute(action,expected)
            raise subprocess.TimeoutExpired('simulated',1)
        cli.c01_call.side_effect=timed_out
        with self.assertRaisesRegex(cli.Refused,'retain run ID'):self.invoke('start')
        self.assertEqual(self.store.record['receipt']['run_id'],RID)
        self.assertEqual((self.cli_state['run_id'],self.cli_state['phase']),(RID,'NEEDS_RESET'))
        self.assertEqual([(x[2],x[3]) for x in self.logs],[('inject','STARTING')])

    def test_incorrect_run_never_reaches_backend(self):
        self.invoke('start');self.backend.call.reset_mock()
        with self.assertRaises(cli.Refused):self.invoke('reset','c'*24)
        self.backend.call.assert_not_called()
    def test_hint_note_require_matching_live_receipt(self):
        self.invoke('start');self.store.record['receipt']['run_id']='c'*24
        for action in ('hint','note'):
            with self.assertRaises(cli.Refused):self.invoke(action,kind='diagnosis')
        self.assertNotIn('hint',[x[2] for x in self.logs])
    def test_reset_event_failure_keeps_identity_and_no_false_success(self):
        self.invoke('start');cli.c01_event.side_effect=OSError('event failed')
        with self.assertRaises(OSError):self.invoke('reset',RID)
        self.assertTrue(self.store.done)
        self.assertEqual((self.cli_state['run_id'],self.cli_state['phase']),(RID,'NEEDS_RESET'))

class ReportTests(unittest.TestCase):
    def test_c01_pass_check_never_counts_as_full(self):
        base={'drill_id':'C01','attempt_id':ATTEMPT,'run_id':RID,'boot_id':'boot','monotonic_ns':1}
        for checks,expected in [([{'event':'check','result':'PASS'}],'INCOMPLETE'),([{'event':'check','result':'PARTIAL'},{'event':'check','result':'PASS'}],'PARTIAL'),([{'event':'check','result':'PARTIAL'},{'event':'check','result':'PENDING'}],'PENDING')]:
            events=[dict(base,event='inject',result='PASS')]+[dict(base,**x) for x in checks]
            row=report.summarize(map(json.dumps,events))['attempts'][0]
            self.assertEqual(row['status'],expected);self.assertIsNone(row['mttr_proxy_seconds'])
    def test_mixed_run_ids_are_invalid_and_missing_id_is_not_adopted(self):
        base=dict(drill_id='C01',attempt_id=ATTEMPT,run_id=RID,event='inject',result='PASS')
        conflict=dict(base,run_id='c'*24,event='check',result='PARTIAL')
        row=report.summarize(map(json.dumps,[base,conflict]))['attempts'][0]
        self.assertEqual(row['status'],'INVALID');self.assertIsNone(row['run_id'])
        missing=dict(base);missing.pop('run_id')
        self.assertEqual(report.summarize([json.dumps(missing)])['invalid_lines'],1)

    def test_partial_without_inject_confirmation_is_incomplete(self):
        events=[dict(drill_id='C01',attempt_id=ATTEMPT,run_id=RID,event='check',result='PARTIAL')]
        self.assertEqual(report.summarize(map(json.dumps,events))['attempts'][0]['status'],'INCOMPLETE')

if __name__=='__main__':unittest.main()