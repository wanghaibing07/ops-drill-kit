import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace(LOCK_EX=1,flock=lambda *a:None))
spec=importlib.util.spec_from_file_location('l02_versioned_cli',Path(__file__).resolve().parents[2]/'scripts/opsdrill_cli.py')
cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
RID='a'*24
class VersionRouting(unittest.TestCase):
    def args(self,command):
        return types.SimpleNamespace(drill='L02',command=command,variant=None,expect_run_id=RID,n04_version=None)
    def test_start_persists_version_and_uses_matching_owner_verifier(self):
        import json
        args=self.args('start');args.expect_run_id=None
        writes=[]
        receipt={'receipt':'L02_CONFIG_OWNER_V1','run_id':RID,'timer':'opsdrill-l02-recover-'+RID+'.timer'}
        cp=types.SimpleNamespace(returncode=0,stdout=json.dumps(receipt),stderr='')
        with mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'),mock.patch.object(cli,'open_lock',return_value=3), \
             mock.patch.object(cli.os,'close'),mock.patch.object(cli,'read_state',return_value=None),mock.patch.object(cli,'script_path'), \
             mock.patch.object(cli,'allocate_id',return_value='L02-20261113-123456'),mock.patch.object(cli,'event'), \
             mock.patch.object(cli,'write_state',side_effect=lambda d,s:writes.append(dict(s))),mock.patch.object(cli,'invoke',return_value=cp) as call, \
             mock.patch.object(cli,'l02_command',return_value=['owner']) as owner,mock.patch.object(cli.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.action(args),0)
        self.assertEqual(writes[0]['l02_version'],'recovery-v2')
        self.assertEqual(writes[-1]['phase'],'ACTIVE')
        call.assert_called_once_with('L02','inject',(),capture=True,l02_version='recovery-v2')
        owner.assert_called_once_with('verify-owner',(RID,),'recovery-v2')
    def test_check_routes_recorded_version(self):
        for version in ('legacy','recovery-v2'):
            state={'phase':'ACTIVE','run_id':RID,'attempt_id':'L02-20261113-123456','timer':'opsdrill-l02-recover-'+RID+'.timer','l02_version':version}
            cp=types.SimpleNamespace(returncode=1,stdout='L02 fault confirmed',stderr='')
            with self.subTest(version=version),mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'), \
                 mock.patch.object(cli,'open_lock',return_value=3),mock.patch.object(cli.os,'close'),mock.patch.object(cli,'read_state',return_value=state), \
                 mock.patch.object(cli,'invoke',return_value=cp) as call,mock.patch.object(cli,'event'),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.action(self.args('check')),1)
            call.assert_called_once_with('L02','check',(RID,),capture=True,l02_version=version)
    def test_unknown_version_refused(self):
        with self.assertRaisesRegex(cli.Refused,'unknown L02 version'):cli.l02_command('inspect-clean',version='invalid')
    def test_reset_routes_recorded_version(self):
        state={'phase':'ACTIVE','run_id':RID,'attempt_id':'L02-20261113-123456','l02_version':'recovery-v2'}
        with mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'),mock.patch.object(cli,'open_lock',return_value=3), \
             mock.patch.object(cli.os,'close'),mock.patch.object(cli.os,'unlink'),mock.patch.object(cli,'read_state',return_value=state), \
             mock.patch.object(cli,'invoke',return_value=0) as call,mock.patch.object(cli,'event'):
            self.assertEqual(cli.action(self.args('reset')),0)
        call.assert_called_once_with('L02','reset',(RID,),l02_version='recovery-v2')
    def test_resolve_routes_recorded_version(self):
        state={'phase':'ACTIVE','run_id':RID,'attempt_id':'L02-20261113-123456','l02_version':'recovery-v2'}
        with mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'),mock.patch.object(cli,'open_lock',return_value=3), \
             mock.patch.object(cli.os,'close'),mock.patch.object(cli,'read_state',return_value=state), \
             mock.patch.object(cli,'invoke',return_value=0) as call:
            self.assertEqual(cli.action(self.args('resolve')),0)
        call.assert_called_once_with('L02','resolve',(RID,),l02_version='recovery-v2')
    def test_no_state_checks_legacy_without_touching_resources(self):
        with mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'),mock.patch.object(cli,'open_lock',return_value=3), \
             mock.patch.object(cli.os,'close'),mock.patch.object(cli,'read_state',return_value=None), \
             mock.patch.object(cli,'l02_clean',return_value=0) as clean:
            self.assertEqual(cli.action(self.args('reset')),0)
        clean.assert_called_once_with('legacy')

if __name__=='__main__':unittest.main()
