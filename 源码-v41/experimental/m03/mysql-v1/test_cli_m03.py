import argparse
import contextlib
import copy
import hashlib
import importlib.util
import json
import io
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import MagicMock, Mock, patch

if sys.platform != 'linux':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
HERE = Path(__file__).resolve().parent

def load(name, filename):
    paths = {'opsdrill_cli.m03.candidate.py': HERE.parents[2] / 'scripts/opsdrill_cli.py', 'install_m03_mysql.py': HERE.parents[2] / 'scripts/install_m03_mysql.py'}
    spec = importlib.util.spec_from_file_location(name, paths.get(filename, HERE / filename))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

cli = load('m03_cli', 'opsdrill_cli.m03.candidate.py')
installer = load('install_m03', 'install_m03_mysql.py')
life = load('mysql_life_for_cli', 'mysql_lifecycle.py')
RID = 'a' * 24
ATTEMPT = 'M03-20261113-123456'

def args(command, rid=RID):
    return argparse.Namespace(drill='M03', command=command, expect_run_id=rid,
                              n04_version=None, variant=None)

def cp(status, code=0, **extra):
    return subprocess.CompletedProcess([], code, json.dumps({'run_id':RID,'status':status,**extra}), '')

def active(phase='ACTIVE'):
    return {'drill_id':'M03','attempt_id':ATTEMPT,'phase':phase,'run_id':RID,'m03_version':'mysql-v1'}

class CliTests(unittest.TestCase):
    def call(self, command, current, responses, expect=RID):
        history=[]
        def write(_drill, value): history.append(copy.deepcopy(value))
        def invoke(action, rid):
            self.assertEqual(rid,RID)
            if command=='start':
                self.assertTrue(history)
                self.assertEqual((history[0]['run_id'],history[0]['phase']), (RID,'STARTING'))
            item=responses.pop(0)
            if isinstance(item,Exception): raise item
            return item
        patches=[patch.object(cli,'require_root'),patch.object(cli,'safe_dir'),
                 patch.object(cli,'open_lock',return_value=42),patch.object(cli.os,'close'),
                 patch.object(cli,'read_state',return_value=current),patch.object(cli,'allocate_id',return_value=ATTEMPT),
                 patch.object(cli,'event'),patch.object(cli,'write_state',side_effect=write),
                 patch.object(cli.secrets,'token_hex',return_value=RID),patch.object(cli,'m03_invoke',side_effect=invoke),
                 patch.object(cli.os,'unlink')]
        for item in patches: item.start(); self.addCleanup(item.stop)
        try:
            result=cli.action(args(command, expect))
            return result,history,None
        except Exception as exc:
            return None,history,exc

    def test_start_saves_id_before_all_three_steps_and_confirms_1040(self):
        responses=[cp('READY',db_scope='isolated_socket_only'),cp('INJECTED'),
                   cp('FAULT',1,sleep_connections=8,mysql_error=1040)]
        result,history,error=self.call('start',None,responses,None)
        self.assertIsNone(error)
        self.assertEqual(result,0)
        self.assertEqual(history[-1]['phase'],'ACTIVE')
        self.assertFalse(responses)

    def test_failed_start_preserves_preallocated_identity(self):
        result,history,error=self.call('start',None,[cp('READY',db_scope='isolated_socket_only'),
                          cli.Refused('lost response')],None)
        self.assertIsInstance(error,cli.Refused)
        self.assertEqual((history[-1]['phase'],history[-1]['run_id']),('NEEDS_RESET',RID))

    def test_wrong_identity_rejected_before_call(self):
        result,history,error=self.call('check',active(),[], 'b'*24)
        self.assertIsInstance(error,cli.Refused)
        self.assertEqual(history,[])

    def test_fault_and_recovery_checks_map_results(self):
        cases=[(cp('FAULT',1,sleep_connections=8,mysql_error=1040),1),
               (cp('RECOVERED',sleep_connections=0,connection='OK'),0)]
        for response,code in cases:
            with self.subTest(code=code):
                result,history,error=self.call('check',active(),[response])
                self.assertIsNone(error)
                self.assertEqual(result,code)

    def test_bad_evidence_fails_closed_and_preserves_state(self):
        for response in [cp('READY',sleep_connections=0,connection='OK'),
                         cp('FAULT',1,sleep_connections=8,mysql_error=1045),
                         cp('FAULT',0,sleep_connections=8,mysql_error=1040),
                         cp('RECOVERED',sleep_connections=1,connection='OK')]:
            with self.subTest(output=response.stdout):
                result,history,error=self.call('check',active(),[response])
                self.assertIsInstance(error,cli.Refused)
                self.assertEqual(history[-1]['phase'],'NEEDS_RESET')

    def test_resolve_requires_followup_recovery(self):
        result,_,error=self.call('resolve',active(),[cp('RELEASED'),cp('RECOVERED',sleep_connections=0,connection='OK')])
        self.assertIsNone(error)
        self.assertEqual(result,0)
        result,history,error=self.call('resolve',active(),[cp('RELEASED'),cp('FAULT',1,sleep_connections=8,mysql_error=1040)])
        self.assertIsInstance(error,cli.Refused)
        self.assertEqual(history[-1]['phase'],'NEEDS_RESET')

    def test_reset_accepts_starting_and_receipt_for_repeat(self):
        for initial in [active('STARTING'),None]:
            with self.subTest(initial=initial):
                result,_,error=self.call('reset',initial,[cp('STOPPED')])
                self.assertIsNone(error)
                self.assertEqual(result,0)

    def test_reset_failure_never_discards_state(self):
        result,history,error=self.call('reset',active(),[cp('STOPPED',2)])
        self.assertIsInstance(error,cli.Refused)
        self.assertEqual(history[-1]['phase'],'NEEDS_RESET')
        cli.os.unlink.assert_not_called()

    def test_duplicate_or_mismatched_json_refused(self):
        responses=[subprocess.CompletedProcess([],1,'{"run_id":"'+RID+'","status":"FAULT","status":"FAULT"}',''),
                   subprocess.CompletedProcess([],1,json.dumps({'run_id':'b'*24,'status':'FAULT','sleep_connections':8,'mysql_error':1040}),'')]
        for response in responses:
            with self.assertRaises(cli.Refused): cli.m03_response(response,RID,'check')

    def test_cli_reports_only_allowed_diagnostic_values(self):
        self.assertEqual(cli.M03_DIAG_STAGES, life.DIAG_STAGES)
        self.assertEqual(cli.M03_DIAG_ERRORS, life.DIAG_ERRORS)
        err = io.StringIO()
        response = subprocess.CompletedProcess([],2,'',json.dumps({'status':'UNCONFIRMED',
            'diagnostic':{'stage':'PREPARE_CREATE','error':'RuntimeError'}, 'secret':'private SQL'}))
        with patch.object(cli, 'm03_command', return_value=['ignored']), \
             patch.object(cli.subprocess, 'run', return_value=response), contextlib.redirect_stderr(err):
            cli.m03_invoke('start',RID)
        self.assertEqual(json.loads(err.getvalue()), {'stage':'PREPARE_CREATE','error':'RuntimeError'})
        self.assertNotIn('private', err.getvalue())
        response.stderr = json.dumps({'status':'UNCONFIRMED',
            'diagnostic':{'stage':'PREPARE_CREATE','error':'private SQL'}})
        err = io.StringIO()
        with patch.object(cli, 'm03_command', return_value=['ignored']), \
             patch.object(cli.subprocess, 'run', return_value=response), contextlib.redirect_stderr(err):
            cli.m03_invoke('start',RID)
        self.assertEqual(err.getvalue(), '')

class InstallTests(unittest.TestCase):
    def test_manifest_matches_actual_exact_bytes_and_cli(self):
        self.assertEqual(installer.MANIFEST,cli.M03_MANIFEST)
        self.assertEqual(set(installer.MANIFEST),{'mysql_lifecycle.py','m04_controller.py','m03_vm_probe.py'})
        for name,digest in installer.MANIFEST.items():
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest)

    def test_installer_rejects_nonroot(self):
        with patch.object(installer.os,'geteuid',return_value=1000,create=True),patch.object(installer.os,'open') as opened:
            with self.assertRaises(RuntimeError): installer.guard()
        opened.assert_not_called()

    def test_foreign_existing_file_is_not_overwritten(self):
        for flag in ('O_NOFOLLOW','O_NONBLOCK','O_CLOEXEC','O_DIRECTORY'):
            if not hasattr(installer.os,flag):
                item=patch.object(installer.os,flag,0,create=True); item.start(); self.addCleanup(item.stop)
        import stat
        files={name:(HERE/name).read_bytes() for name in installer.MANIFEST}
        files['manifest.json']=(json.dumps(installer.MANIFEST,sort_keys=True)+'\n').encode('ascii')
        directory=MagicMock(st_mode=stat.S_IFDIR|0o755,st_uid=0)
        with patch.object(installer.os,'open',side_effect=range(10,18)),patch.object(installer.os,'mkdir'), \
             patch.object(installer.os,'fstat',return_value=directory),patch.object(installer.os,'close'), \
             patch.object(installer.os,'listdir',return_value=['mysql_lifecycle.py']), \
             patch.object(installer,'secure_file',return_value=b'foreign'),patch.object(installer.os,'link') as link:
            with self.assertRaises(RuntimeError): installer.install(files)
        link.assert_not_called()

if __name__=='__main__': unittest.main()
