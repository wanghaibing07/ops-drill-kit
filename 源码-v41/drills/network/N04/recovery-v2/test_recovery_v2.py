import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
HERE=Path(__file__).resolve().parent

def load(name, filename):
    spec=importlib.util.spec_from_file_location(name, HERE/filename)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

life=load('life_v2', 'n04_lifecycle.py')
cli=load('cli_v2', 'opsdrill_cli.recovery-v2.candidate.py')
installer=load('install_v2', 'install_n04_v2.py')
RID='a'*24
RECORD={'pid':123,'invocation':'b'*32,'start_ticks':10,'boot_id':'boot','sources':{'v':'hash'}}
INTENT={'sources':{'v':'hash'},'boot_id':'boot','token':'c'*64}

class LifecycleTests(unittest.TestCase):
    def test_reservation_precedes_launch_and_reuse_never_launches(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); seen=[]
            with mock.patch.object(life,'protected_sources',return_value={'v':'hash'}), \
                 mock.patch.object(life,'base',return_value=root), \
                 mock.patch.object(life,'sync_dir',side_effect=lambda p:seen.append('sync')), \
                 mock.patch.object(life,'write_intent',side_effect=lambda *a:seen.append('intent') or INTENT), \
                 mock.patch.object(life,'properties_absent',side_effect=lambda *a:seen.append('absent') or True), \
                 mock.patch.object(life,'command',side_effect=lambda *a:seen.append('launch')), \
                 mock.patch.object(life.os.path,'lexists',return_value=True), \
                 mock.patch.object(life,'reconcile',return_value={'ok':True}):
                self.assertEqual(life.start(RID),{'ok':True})
                self.assertEqual(seen,['sync','intent','absent','launch'])
                with self.assertRaises(FileExistsError): life.start(RID)
                self.assertEqual(seen.count('launch'),1)

    def test_reconcile_requires_live_identity_and_matching_intent(self):
        ok={'ok':True,'result':{'event':'injected'}}
        with mock.patch.object(life,'read_intent',return_value=INTENT), \
             mock.patch.object(life,'identity',return_value=RECORD), \
             mock.patch.object(life,'request',return_value=ok) as request, \
             mock.patch.object(life,'save_record') as save:
            self.assertEqual(life.reconcile(RID)['receipt'],'N04_OWNER_V2')
            request.assert_called_once_with(RID,'status',RECORD); save.assert_called_once_with(RID,RECORD)
        with mock.patch.object(life,'read_intent',return_value=dict(INTENT,boot_id='other')), \
             mock.patch.object(life,'identity',return_value=RECORD), \
             mock.patch.object(life,'request') as request, mock.patch.object(life,'save_record') as save:
            with self.assertRaises(RuntimeError): life.reconcile(RID)
            request.assert_not_called(); save.assert_not_called()
        with mock.patch.object(life,'read_intent',return_value=INTENT), \
             mock.patch.object(life,'identity',side_effect=RuntimeError('unit absent')), \
             mock.patch.object(life,'save_record') as save:
            with self.assertRaises(RuntimeError): life.reconcile(RID)
            save.assert_not_called()

    def test_reconcile_existing_record_must_match(self):
        with mock.patch.object(life,'read_intent',return_value=INTENT), \
             mock.patch.object(life,'identity',return_value=RECORD), \
             mock.patch.object(life,'request',return_value={'ok':True,'result':{'event':'injected'}}), \
             mock.patch.object(life,'save_record',side_effect=FileExistsError), \
             mock.patch.object(life,'read_record',return_value=dict(RECORD,pid=456)):
            with self.assertRaises(RuntimeError): life.reconcile(RID)

    def test_nonmatching_service_token_is_rejected(self):
        props={'Id':life.unit_name(RID),'LoadState':'loaded','ActiveState':'active',
               'Transient':'yes','FragmentPath':'/run/systemd/transient/'+life.unit_name(RID),
               'ControlGroup':'/system.slice/'+life.unit_name(RID),'MainPID':'123',
               'InvocationID':'b'*32,'ExecStart':'path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+str(Path(life.__file__).absolute())+' serve '+RID+' '+'d'*64+' ;'}
        with mock.patch.object(life,'read_intent',return_value=INTENT):
            with self.assertRaises(RuntimeError): life.validate_unit(RID,props)

    def test_missing_identity_reconcile_failure_never_claims_reset(self):
        with mock.patch.object(life.sys,'platform','linux'), mock.patch.object(life,'guard'), \
             mock.patch.object(life,'protected_sources'), \
             mock.patch.object(life,'read_record',side_effect=FileNotFoundError), \
             mock.patch.object(life,'reconcile',side_effect=RuntimeError('unknown or inactive')), \
             mock.patch.object(life,'request') as request, mock.patch.object(life,'completion') as completion:
            with self.assertRaises(RuntimeError): life.main(['reset',RID])
            request.assert_not_called(); completion.assert_not_called()

    def test_corrupt_record_is_not_replaced_by_reconcile(self):
        with mock.patch.object(life.sys,'platform','linux'), mock.patch.object(life,'guard'), \
             mock.patch.object(life,'protected_sources'), \
             mock.patch.object(life,'read_record',side_effect=ValueError('corrupt')), \
             mock.patch.object(life,'reconcile') as reconcile:
            with self.assertRaises(ValueError): life.main(['reset',RID])
            reconcile.assert_not_called()

    def test_reset_response_loss_does_not_create_completion(self):
        with mock.patch.object(life.sys,'platform','linux'), mock.patch.object(life,'guard'), \
             mock.patch.object(life,'protected_sources'), mock.patch.object(life,'read_record',return_value=RECORD), \
             mock.patch.object(life,'repeat_reset',return_value=False), \
             mock.patch.object(life,'request',side_effect=OSError('response lost')), \
             mock.patch.object(life,'completion') as completion:
            with self.assertRaises(OSError): life.main(['reset',RID])
            completion.assert_not_called()

    def test_new_installer_hashes_and_isolated_paths(self):
        import hashlib
        for name,digest in installer.MANIFEST.items():
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest)
        self.assertEqual(installer.MANIFEST,cli.N04_V2_MANIFEST)
        self.assertNotEqual(life.INSTALL,Path('/usr/local/libexec/opsdrill/n04'))
        self.assertNotEqual(life.ROOT,Path('/run/opsdrill-n04'))

class CliTests(unittest.TestCase):
    def args(self,command,rid=None,version=None):
        return argparse.Namespace(drill='N04',command=command,expect_run_id=rid,
                                  variant=None,actor='agent',n04_version=version)
    def test_id_and_version_are_durable_before_start(self):
        states=[]; calls=[]
        def write(drill,state): states.append(dict(state))
        def invoke(drill, action, extra=(), capture=False, **kw):
            calls.append((action,extra,kw)); self.assertEqual(states[-1]['run_id'],RID)
            self.assertEqual(states[-1]['phase'],'STARTING')
            self.assertEqual(states[-1]['n04_version'],'recovery-v2')
            raise RuntimeError('interruption')
        with mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'), \
             mock.patch.object(cli,'open_lock',return_value=99),mock.patch.object(cli.os,'close'), \
             mock.patch.object(cli,'read_state',return_value=None),mock.patch.object(cli,'script_path'), \
             mock.patch.object(cli,'allocate_id',return_value='N04-20261113-123456'), \
             mock.patch.object(cli,'event'),mock.patch.object(cli,'write_state',side_effect=write), \
             mock.patch.object(cli,'invoke',side_effect=invoke),mock.patch.object(cli.os,'urandom',return_value=bytes.fromhex(RID)):
            with self.assertRaises(RuntimeError): cli.action(self.args('start'))
        self.assertEqual(calls[0][1],(RID,)); self.assertEqual(states[-1]['run_id'],RID)
        self.assertEqual(states[-1]['phase'],'NEEDS_RESET')

    def reset_case(self,state,version=None):
        cp=types.SimpleNamespace(returncode=2,stdout='{}',stderr='')
        with mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'), \
             mock.patch.object(cli,'open_lock',return_value=99),mock.patch.object(cli.os,'close'), \
             mock.patch.object(cli,'read_state',return_value=state),mock.patch.object(cli,'invoke',return_value=cp) as inv, \
             mock.patch.object(cli,'write_state'),mock.patch.object(cli,'event'),contextlib.redirect_stdout(io.StringIO()):
            result=cli.action(self.args('reset',RID,version))
        return result,inv

    def test_version_routing_and_starting_recovery(self):
        state={'drill_id':'N04','attempt_id':'N04-20261113-123456','phase':'STARTING','run_id':RID,'n04_version':'recovery-v2'}
        _,inv=self.reset_case(state); self.assertEqual(inv.call_args.kwargs['n04_version'],'recovery-v2')
        state.pop('n04_version'); state['phase']='ACTIVE'
        _,inv=self.reset_case(state); self.assertEqual(inv.call_args.kwargs['n04_version'],'legacy')
        _,inv=self.reset_case(None); self.assertEqual(inv.call_args.kwargs['n04_version'],'legacy')
        _,inv=self.reset_case(None,'recovery-v2'); self.assertEqual(inv.call_args.kwargs['n04_version'],'recovery-v2')
        with self.assertRaises(cli.Refused): self.reset_case(state,'recovery-v2')

if __name__=='__main__': unittest.main()
