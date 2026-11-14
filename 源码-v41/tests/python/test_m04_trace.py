import contextlib, importlib.util, io, sys, types, unittest
from pathlib import Path
from unittest import mock

if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace(LOCK_EX=1,flock=lambda *a:None))
spec=importlib.util.spec_from_file_location('m04_trace_cli',Path(__file__).resolve().parents[2]/'scripts/opsdrill_cli.py')
cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
RID='0123456789abcdef'; ATTEMPT='M04-20261113-123456'

class TraceTests(unittest.TestCase):
    def state(self,version='synthetic-v3'):
        return {'drill_id':'M04','attempt_id':ATTEMPT,'phase':'ACTIVE','run_id':RID,'m04_version':version}
    def args(self,command):return types.SimpleNamespace(command=command,variant=None)
    def test_v3_events_bind_identity_and_expected_auditor(self):
        with mock.patch.object(cli,'event') as event,mock.patch.object(cli,'m04_command') as command:
            cli.m04_event(self.state(),'inject','PASS','auto',verified=True)
        command.assert_called_once_with('check',RID,'synthetic-v3')
        event.assert_called_once_with('M04',ATTEMPT,'inject','PASS','auto',{'run_id':RID,'m04_version':'synthetic-v3','expected_auditor_sha256':cli.M04_V2_MANIFEST['pitr_audit.py'],'verified_auditor_sha256':cli.M04_V2_MANIFEST['pitr_audit.py']})
    def test_legacy_events_do_not_invent_auditor(self):
        with mock.patch.object(cli,'event') as event: cli.m04_event(self.state('synthetic-v2'),'reset','PASS','auto')
        self.assertEqual(event.call_args.args[-1],{'run_id':RID,'m04_version':'synthetic-v2'})
    def test_v4_events_keep_auditor_identity(self):
        with mock.patch.object(cli,'event') as event,mock.patch.object(cli,'m04_command') as command:
            cli.m04_event(self.state('synthetic-v4'),'reset','PASS','auto',verified=True)
        command.assert_called_once_with('check',RID,'synthetic-v4')
        self.assertEqual(event.call_args.args[-1]['verified_auditor_sha256'],cli.M04_V4_MANIFEST['pitr_audit.py'])
    def test_resolve_and_reset_record_intent_and_outcome(self):
        state=self.state()
        with mock.patch.object(cli,'event') as event,mock.patch.object(cli,'m04_command'),mock.patch.object(cli,'m04_invoke',return_value={'status':'RECOVERED'}),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.m04_action(self.args('resolve'),state,RID),0)
        self.assertEqual([(c.args[2],c.args[3]) for c in event.call_args_list],[('resolve','STARTING'),('resolve','PASS')])
        with mock.patch.object(cli,'event') as event,mock.patch.object(cli,'m04_command'),mock.patch.object(cli,'m04_invoke',return_value={'status':'STOPPED'}),mock.patch.object(cli.os,'unlink'),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.m04_action(self.args('reset'),state,RID),0)
        self.assertEqual([(c.args[2],c.args[3]) for c in event.call_args_list],[('reset','STARTING'),('reset','PASS')])
    def test_invalid_identity_refused(self):
        state=self.state();state['run_id']='invalid'
        with mock.patch.object(cli,'event') as event,self.assertRaises(cli.Refused):cli.m04_event(state,'inject','STARTING','auto')
        event.assert_not_called()

if __name__=='__main__':unittest.main()
