import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace(LOCK_EX=1,flock=lambda *a:None))
spec=importlib.util.spec_from_file_location('m04_versioned_cli',Path(__file__).resolve().parents[2]/'scripts/opsdrill_cli.py')
cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
RID='a'*16

class RoutingTests(unittest.TestCase):
    def args(self,command):return types.SimpleNamespace(command=command,actor='agent',variant=None)
    def test_start_persists_v4_before_invocation(self):
        writes=[]
        def save(drill,state):writes.append(dict(state))
        with mock.patch.object(cli,'allocate_id',return_value='M04-20261113-123456'),mock.patch.object(cli.secrets,'token_hex',return_value=RID), \
             mock.patch.object(cli,'write_state',side_effect=save),mock.patch.object(cli,'event'),mock.patch.object(cli,'m04_command'), \
             mock.patch.object(cli,'m04_invoke',side_effect=[{'status':'FAULT'},{'status':'FAULT'}]) as invoke,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.m04_action(self.args('start'),None,None),0)
        self.assertEqual(writes[0]['m04_version'],'synthetic-v4')
        self.assertEqual(invoke.call_args_list,[mock.call('start',RID,'synthetic-v4'),mock.call('check',RID,'synthetic-v4')])
    def test_existing_version_routes_to_its_own_controller(self):
        for version in ('synthetic-v1','synthetic-v2','synthetic-v3','synthetic-v4'):
            state={'phase':'ACTIVE','attempt_id':'M04-20261113-123456','run_id':RID,'m04_version':version}
            with self.subTest(version=version),mock.patch.object(cli,'m04_invoke',return_value={'status':'RECOVERED'}) as invoke, \
                 mock.patch.object(cli,'event'),mock.patch.object(cli,'m04_command'),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.m04_action(self.args('check'),state,RID),0)
            invoke.assert_called_once_with('check',RID,version)
    def test_reset_without_state_uses_legacy_controller(self):
        with mock.patch.object(cli,'completed_m04_version',return_value='synthetic-v1'),mock.patch.object(cli,'m04_invoke',return_value={'status':'STOPPED'}) as invoke,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.m04_action(self.args('reset'),None,RID),0)
        invoke.assert_called_once_with('reset',RID,'synthetic-v1')
    def test_audit_digest_requires_fix_for_new_runs(self):
        old = '435103f2a50e37300f0746fea814bf479a35234f77d0c4e7944c157b0cf294cd'
        fixed = '3b6d5fa1ee4c5227d3ae33a825b92bac8c96d6b054a80bfda2537ea03cb6c51e'
        for version in ('synthetic-v1','synthetic-v2','synthetic-v3','synthetic-v4'):
            self.assertTrue(cli.m04_digest_matches('pitr_audit.py', fixed, fixed, version, 'start'))
            self.assertFalse(cli.m04_digest_matches('pitr_audit.py', fixed, old, version, 'start'))
        for version in ('synthetic-v1','synthetic-v2'):
            self.assertTrue(cli.m04_digest_matches('pitr_audit.py', fixed, old, version, 'reset'))
        self.assertFalse(cli.m04_digest_matches('pitr_audit.py', fixed, old, 'synthetic-v3', 'reset'))
        self.assertFalse(cli.m04_digest_matches('pitr_audit.py', fixed, old, 'synthetic-v4', 'reset'))
        self.assertFalse(cli.m04_digest_matches('sealed_replay.py', fixed, old, 'synthetic-v2', 'reset'))
        self.assertFalse(cli.m04_digest_matches('pitr_audit.py', fixed, '0' * 64, 'synthetic-v2', 'reset'))
    def test_unknown_version_fails_before_inspection(self):
        with self.assertRaisesRegex(cli.Refused,'unknown M04 version'):
            cli.m04_command('check',RID,'unknown')

if __name__=='__main__':unittest.main()
