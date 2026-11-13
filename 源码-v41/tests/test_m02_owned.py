import importlib.util
import io
import json
import os
import sys
import types
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

# These modules exist on the target Linux host; this suite also runs offline on Windows.
for name in ('fcntl', 'pwd', 'grp', 'pymysql'):
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = types.ModuleType(name)

ROOT = Path(__file__).resolve().parents[1]
def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

cli = load('m02_cli_candidate', 'scripts/opsdrill_cli.py')
deadlock = load('m02_deadlock_candidate', 'drills/mysql/M02/m02_deadlock.py')
installer = load('m02_installer_candidate', 'scripts/install_m02.py')
launcher = load('m02_launcher_candidate', 'drills/mysql/M02/m02_launcher.py')
RID = 'a' * 24
OTHER = 'b' * 24
ATTEMPT = 'M02-20261113-123456'

def args(command):
    return SimpleNamespace(command=command, variant=None, actor='agent')

class CliOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.patches = [
            mock.patch.object(cli, 'm02_command', side_effect=lambda action, rid, require_reset_completed=False: [action, rid, require_reset_completed]),
            mock.patch.object(cli, 'allocate_id', return_value=ATTEMPT),
            mock.patch.object(cli, 'event'),
            mock.patch.object(cli, 'write_state'),
            mock.patch.object(cli.secrets, 'token_hex', return_value=RID),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_start_persists_identity_before_running_real_controller(self):
        def run(command, **kwargs):
            saved = cli.write_state.call_args_list[0].args[1]
            self.assertEqual(saved['run_id'], RID)
            self.assertEqual(saved['phase'], 'STARTING')
            self.assertEqual(command, ['inject', RID, False])
            return SimpleNamespace(returncode=0, stdout=json.dumps({'receipt':'M02_DEADLOCK_OWNER_V1','run_id':RID}), stderr='')
        with mock.patch.object(cli.subprocess, 'run', side_effect=run), mock.patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(cli.m02_action(args('start'), None, None), 0)
        self.assertEqual(cli.write_state.call_args.args[1]['phase'], 'ACTIVE')

    def test_failed_start_keeps_identity_for_inspection(self):
        cp = SimpleNamespace(returncode=1, stdout='', stderr='failure')
        with mock.patch.object(cli.subprocess, 'run', return_value=cp), mock.patch('sys.stdout', new_callable=io.StringIO), mock.patch('sys.stderr', new_callable=io.StringIO):
            self.assertEqual(cli.m02_action(args('start'), None, None), 1)
        state = cli.write_state.call_args.args[1]
        self.assertEqual((state['phase'],state['run_id']), ('NEEDS_RESET',RID))

    def test_bad_receipt_is_not_activated(self):
        cp = SimpleNamespace(returncode=0, stdout=json.dumps({'receipt':'M02_DEADLOCK_OWNER_V1','run_id':OTHER}), stderr='')
        with mock.patch.object(cli.subprocess, 'run', return_value=cp), mock.patch('sys.stdout', new_callable=io.StringIO):
            with self.assertRaises(cli.Refused): cli.m02_action(args('start'),None,None)
        self.assertEqual(cli.write_state.call_args.args[1]['phase'], 'NEEDS_RESET')

    def test_missing_or_wrong_id_never_invokes_controller(self):
        state={'phase':'ACTIVE','run_id':RID,'attempt_id':ATTEMPT}
        with mock.patch.object(cli.subprocess, 'run') as run:
            for expected in (None, OTHER):
                with self.assertRaises(cli.Refused): cli.m02_action(args('reset'),state,expected)
            run.assert_not_called()

    def test_check_in_needs_reset_requires_completion_record(self):
        state={'phase':'NEEDS_RESET','run_id':RID,'attempt_id':ATTEMPT}
        cp=SimpleNamespace(returncode=1, stdout='', stderr='no completion record')
        with mock.patch.object(cli.subprocess,'run',return_value=cp) as run, mock.patch('sys.stderr',new_callable=io.StringIO):
            self.assertEqual(cli.m02_action(args('check'),state,RID),1)
            self.assertEqual(run.call_args.args[0],['check',RID,True])

    def test_missing_cli_state_requires_matching_completion_record(self):
        for action in ('check','reset'):
            cp=SimpleNamespace(returncode=0,stdout='',stderr='')
            with mock.patch.object(cli.subprocess,'run',return_value=cp) as run:
                self.assertEqual(cli.m02_action(args(action),None,RID),0)
                self.assertEqual(run.call_args.args[0],[action,RID,True])

    def test_reset_failure_preserves_state_and_success_deletes_it(self):
        for code in (1,0):
            state={'phase':'STARTING','run_id':RID,'attempt_id':ATTEMPT}
            cp=SimpleNamespace(returncode=code,stdout='',stderr='')
            with mock.patch.object(cli.subprocess,'run',return_value=cp), mock.patch.object(cli.os,'unlink') as unlink:
                self.assertEqual(cli.m02_action(args('reset'),state,RID),code)
                self.assertEqual(unlink.called, code==0)
                if code: self.assertEqual(state['phase'],'NEEDS_RESET')

    def test_reset_completion_survives_cli_event_failure(self):
        state={'phase':'ACTIVE','run_id':RID,'attempt_id':ATTEMPT}
        cp=SimpleNamespace(returncode=0,stdout='',stderr='')
        with mock.patch.object(cli.subprocess,'run',return_value=cp), \
             mock.patch.object(cli,'event',side_effect=OSError('event write failed')), \
             mock.patch.object(cli.os,'unlink') as unlink:
            with self.assertRaises(OSError): cli.m02_action(args('reset'),state,RID)
            unlink.assert_not_called()
            self.assertEqual(state['phase'],'NEEDS_RESET')
        with mock.patch.object(cli.subprocess,'run',return_value=cp), mock.patch.object(cli.os,'unlink') as unlink:
            self.assertEqual(cli.m02_action(args('reset'),state,RID),0)
            unlink.assert_called_once()

class UnderlyingOwnerTests(unittest.TestCase):
    def call_main(self, action, owner, requested):
        argv=['m02_deadlock.py',action]
        if requested is not None: argv.extend(['--owned-run-id',requested])
        with mock.patch.object(sys,'argv',argv), mock.patch.object(deadlock,'require_root_and_lab'), \
             mock.patch.object(deadlock,'check_dir'), mock.patch.object(deadlock,'check_file'), \
             mock.patch.object(deadlock,'acquire_lock',return_value=123), mock.patch.object(deadlock.os,'close'), \
             mock.patch.object(deadlock.os.path,'lexists',return_value=True), \
             mock.patch.object(deadlock,'read_state',return_value={'owner_run_id':owner}), \
             mock.patch.object(deadlock,'reset') as reset:
            deadlock.main()
            return reset.called

    def test_direct_and_wrong_owner_reset_refused(self):
        for requested in (None,OTHER):
            with self.assertRaises(deadlock.DrillError): self.call_main('reset',RID,requested)
        self.assertTrue(self.call_main('reset',RID,RID))

    def test_legacy_state_cannot_be_claimed(self):
        with self.assertRaises(deadlock.DrillError): self.call_main('reset',None,RID)
        self.assertTrue(self.call_main('reset',None,None))

    def test_evidence_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'evidence.json'
            original=b'{"owner_run_id":"' + RID.encode() + b'"}'
            path.write_bytes(original)
            fake_stat=SimpleNamespace(st_mode=0o100640,st_nlink=1,st_uid=10,st_gid=20,st_size=len(original))
            with mock.patch.object(deadlock,'EVIDENCE_DIR',Path(directory)), \
                 mock.patch.object(deadlock.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=10),create=True), \
                 mock.patch.object(deadlock.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=20),create=True), \
                 mock.patch.object(deadlock.os,'fstat',return_value=fake_stat), \
                 mock.patch.object(deadlock.os,'O_NOFOLLOW',0,create=True), \
                 mock.patch.object(deadlock.os,'O_NONBLOCK',0,create=True):
                digest=hashlib.sha256(original).hexdigest()
                self.assertEqual(deadlock.read_evidence(path,digest)['owner_run_id'],RID)
                path.write_bytes(original.replace(RID.encode(),OTHER.encode()))
                with self.assertRaises(deadlock.DrillError): deadlock.read_evidence(path,digest)

    def test_evidence_digest_and_owner_are_required(self):
        state={'phase':'completed','owner_run_id':RID,'evidence_path':'/tmp/x'}
        with mock.patch.object(deadlock.os.path,'lexists',return_value=True), mock.patch.object(deadlock,'read_state',return_value=state), mock.patch.object(deadlock,'read_evidence') as read:
            with self.assertRaises(deadlock.DrillError): deadlock.check()
            read.assert_not_called()
        state['evidence_sha256']='1'*64
        with mock.patch.object(deadlock.os.path,'lexists',return_value=True), mock.patch.object(deadlock,'read_state',return_value=state), mock.patch.object(deadlock,'read_evidence',return_value={'owner_run_id':OTHER}):
            with self.assertRaises(deadlock.DrillError): deadlock.check()

class CompletionRecordTests(unittest.TestCase):
    def setUp(self):
        self.state={'kind':'m02-deadlock','phase':'completed','owner_run_id':RID,
                    'server_uuid':'server','connection_ids':[11,12],
                    'evidence_path':'/evidence/item.json','evidence_sha256':'a'*64}
        self.saved=[]
        self.patches=[
            mock.patch.object(deadlock.os.path,'lexists',return_value=True),
            mock.patch.object(deadlock,'read_state',side_effect=lambda: dict(self.state)),
            mock.patch.object(deadlock,'write_state',side_effect=self.save),
            mock.patch.object(deadlock,'connect_admin',return_value=object()),
            mock.patch.object(deadlock,'global_snapshot',return_value={'server_uuid':'server','log_bin':1}),
            mock.patch.object(deadlock,'target_status',return_value=deadlock.BASELINE),
            mock.patch.object(deadlock,'transaction_count',return_value=0),
            mock.patch.object(deadlock,'state_ps_wait_count',return_value=0),
            mock.patch.object(deadlock,'close'),
            mock.patch.object(deadlock,'read_evidence',return_value={'owner_run_id':RID,'result':'PASS',
                'deadlock':{'error_code':1213},'mysql':{'global_log_bin_after':1}}),
        ]
        for patch in self.patches:
            patch.start(); self.addCleanup(patch.stop)
    def save(self,state):
        self.state=dict(state); self.saved.append(dict(state))

    def test_check_after_reset_and_repeat_reset(self):
        with mock.patch('sys.stdout',new_callable=io.StringIO):
            deadlock.reset()
            self.assertEqual(self.state['phase'],'reset-completed')
            self.assertEqual(self.state['phase_before_reset'],'completed')
            deadlock.check()
            deadlock.reset()
        self.assertEqual(len(self.saved),1)
        self.assertEqual(self.state['owner_run_id'],RID)

    def test_failed_run_cannot_be_promoted_to_check_pass(self):
        self.state['phase']='failed'
        with mock.patch('sys.stdout',new_callable=io.StringIO):
            deadlock.reset()
            with self.assertRaises(deadlock.DrillError): deadlock.check()

    def test_unhealthy_reset_does_not_write_completion(self):
        with mock.patch.object(deadlock,'target_status',return_value={}), mock.patch('sys.stdout',new_callable=io.StringIO):
            with self.assertRaises(deadlock.DrillError): deadlock.reset()
        self.assertEqual(self.saved,[])

    def test_reset_without_state_fails_closed(self):
        with mock.patch.object(deadlock.os.path,'lexists',return_value=False):
            with self.assertRaises(deadlock.DrillError): deadlock.reset()

    def test_unowned_inject_cannot_replace_cli_record(self):
        self.state['phase']='reset-completed'
        with mock.patch.object(deadlock,'connect_admin') as connect:
            with self.assertRaises(deadlock.DrillError): deadlock.inject()
            connect.assert_not_called()

    def test_completion_flag_rejects_unfinished_or_wrong_owner(self):
        for phase,requested in [('completed',RID),('reset-completed',OTHER)]:
            self.state['phase']=phase
            argv=['m02_deadlock.py','reset','--owned-run-id',requested,'--require-reset-completed']
            with mock.patch.object(sys,'argv',argv), mock.patch.object(deadlock,'require_root_and_lab'), \
                 mock.patch.object(deadlock,'check_dir'), mock.patch.object(deadlock,'check_file'), \
                 mock.patch.object(deadlock,'acquire_lock',return_value=123), mock.patch.object(deadlock.os,'close'), \
                 mock.patch.object(deadlock,'reset') as reset:
                with self.assertRaises(deadlock.DrillError): deadlock.main()
                reset.assert_not_called()

class CliLifecycleIntegrationTests(unittest.TestCase):
    def test_cli_dispatch_reset_check_repeat_and_wrong_id(self):
        cli_state={}
        bottom={'kind':'m02-deadlock','phase':'completed','owner_run_id':RID,
                'server_uuid':'server','connection_ids':[11,12],
                'evidence_path':'/evidence/item.json','evidence_sha256':'a'*64}
        def cli_read(_): return dict(cli_state) if cli_state else None
        def cli_write(_,state): cli_state.clear(); cli_state.update(state)
        def bottom_write(state): bottom.clear(); bottom.update(state)
        def invoke(command,**kwargs):
            out,err=io.StringIO(),io.StringIO()
            argv=['m02_deadlock.py',command[0],'--owned-run-id',command[1]]
            if command[2]: argv.append('--require-reset-completed')
            with mock.patch.object(sys,'argv',argv), mock.patch('sys.stdout',out), mock.patch('sys.stderr',err):
                try: deadlock.main(); code=0
                except deadlock.DrillError as exc: print(str(exc),file=err); code=1
            return SimpleNamespace(returncode=code,stdout=out.getvalue(),stderr=err.getvalue())
        def inject(rid):
            self.assertEqual(cli_state['phase'],'STARTING')
            self.assertEqual(cli_state['run_id'],rid)
        common=[mock.patch.object(cli,'require_root'),mock.patch.object(cli,'safe_dir'),
                mock.patch.object(cli,'open_lock',return_value=123),mock.patch.object(cli.os,'close'),
                mock.patch.object(cli,'read_state',side_effect=cli_read),
                mock.patch.object(cli,'write_state',side_effect=cli_write),
                mock.patch.object(cli,'event'),mock.patch.object(cli,'allocate_id',return_value=ATTEMPT),
                mock.patch.object(cli.secrets,'token_hex',return_value=RID),
                mock.patch.object(cli,'m02_command',side_effect=lambda a,r,require_reset_completed=False:[a,r,require_reset_completed]),
                mock.patch.object(cli.subprocess,'run',side_effect=invoke),
                mock.patch.object(cli.os,'unlink',side_effect=lambda _:cli_state.clear()),
                mock.patch.object(deadlock,'require_root_and_lab'),mock.patch.object(deadlock,'check_dir'),
                mock.patch.object(deadlock,'check_file'),mock.patch.object(deadlock,'acquire_lock',return_value=123),
                mock.patch.object(deadlock.os.path,'lexists',return_value=True),
                mock.patch.object(deadlock,'read_state',side_effect=lambda:dict(bottom)),
                mock.patch.object(deadlock,'write_state',side_effect=bottom_write),
                mock.patch.object(deadlock,'inject',side_effect=inject),
                mock.patch.object(deadlock,'connect_admin',return_value=object()),
                mock.patch.object(deadlock,'global_snapshot',return_value={'server_uuid':'server','log_bin':1}),
                mock.patch.object(deadlock,'target_status',return_value=deadlock.BASELINE),
                mock.patch.object(deadlock,'transaction_count',return_value=0),
                mock.patch.object(deadlock,'state_ps_wait_count',return_value=0),mock.patch.object(deadlock,'close'),
                mock.patch.object(deadlock,'read_evidence',return_value={'owner_run_id':RID,'result':'PASS',
                    'deadlock':{'error_code':1213},'mysql':{'global_log_bin_after':1}})]
        for patch in common: patch.start(); self.addCleanup(patch.stop)
        def run(command,rid=None):
            return cli.action(SimpleNamespace(command=command,drill='M02',actor='agent',variant=None,
                                               expect_run_id=rid,n04_version=None))
        with mock.patch('sys.stdout',new_callable=io.StringIO), mock.patch('sys.stderr',new_callable=io.StringIO):
            self.assertEqual(run('start'),0)
            self.assertEqual(run('check',RID),0)
            self.assertEqual(run('reset',RID),0)
            self.assertEqual(bottom['phase'],'reset-completed')
            self.assertFalse(cli_state)
            self.assertEqual(run('check',RID),0)
            self.assertEqual(run('reset',RID),0)
            self.assertNotEqual(run('reset',OTHER),0)
            self.assertNotEqual(run('check',OTHER),0)

class InstallationTests(unittest.TestCase):
    def test_manifest_matches_sources_and_both_wrappers_forward(self):
        for name, digest in installer.MANIFEST.items():
            data=(ROOT/'drills/mysql/M02'/name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.assertEqual(cli.M02_MANIFEST[name],digest)
        with mock.patch.object(cli,'m02_trusted_file') as trusted:
            command=cli.m02_command('check',RID)
        self.assertEqual(trusted.call_count,2)
        self.assertEqual(command[:4],['/usr/bin/python3.11','-I','-S','-B'])
        self.assertEqual(command[-3:],['check','--owned-run-id',RID])
        for filename in ('m02_deadlock.sh','m02_deadlock.py'):
            text=(ROOT/'scripts'/filename).read_text(encoding='utf-8')
            self.assertIn('/usr/local/libexec/opsdrill/m02/m02_launcher.py',text)
            self.assertIn('-I',text); self.assertIn('-S',text); self.assertIn('-B',text)

    def test_dependency_failure_precedes_any_install(self):
        with mock.patch.object(sys,'argv',['install_m02.py','/staging']), \
             mock.patch.object(installer,'guard'), mock.patch.object(installer,'secure_installer'), \
             mock.patch.object(installer,'source_files',return_value={}), \
             mock.patch.object(installer,'verify_dependencies',side_effect=RuntimeError('RPM verification failed')), \
             mock.patch.object(installer,'install') as install:
            with self.assertRaises(RuntimeError): installer.main()
            install.assert_not_called()

    def test_untrusted_package_tree_is_rejected(self):
        bad=SimpleNamespace(st_uid=1000, st_mode=0o40755)
        with mock.patch.object(Path,'lstat',return_value=bad):
            with self.assertRaises(RuntimeError): launcher.check_site(Path('/untrusted'))

    def test_controller_and_launcher_cannot_be_replaced_silently(self):
        with mock.patch.object(cli,'m02_trusted_file',side_effect=cli.Refused('version mismatch')):
            with self.assertRaises(cli.Refused): cli.m02_command('reset',RID)

if __name__ == '__main__':
    unittest.main()
