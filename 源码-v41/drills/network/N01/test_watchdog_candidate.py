import importlib.util
import hashlib
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
spec = importlib.util.spec_from_file_location('n01_watchdog', Path(__file__).with_name('n01_watchdog.py'))
wd = importlib.util.module_from_spec(spec); spec.loader.exec_module(wd)


def fixture():
    rid = 'a'*24
    state = {'run_id':rid, 'n02_run_id':'b'*24, 'pid':123, 'identity':[1,2,'/usr/bin/python3'], 'version':1}
    return {'version':1, 'run_id':rid, 'state':state,
            'topology':{'run_id':'b'*24, 'namespaces':{'od-client':1,'od-router':2,'od-server':3}, 'baseline':'c'*64,
                        'intent':False, 'injected':None, 'timer':None, 'helper_sha256':None, 'armed_at':None},
            'namespace_ids':{'od-client':[10,1,101],'od-router':[10,2,102],'od-server':[10,3,103]},
            'state_file':[1,11,111], 'resolver':[1,12,112], 'socket':[1,13,113],
            'helper_sha256':'d'*64, 'boot_id':'01234567-89ab-cdef-0123-456789abcdef'}


class ManifestTests(unittest.TestCase):
    def test_run_id_and_private_identity_are_strict(self):
        obj = fixture(); wd.validate_manifest(obj, obj['run_id'])
        for change in ({'run_id':'e'*24}, {'resolver':[1]}, {'state_file':[1,True,111]}, {'version':True}):
            with self.assertRaises(wd.Refused): wd.validate_manifest(obj | change, obj['run_id'])
        with self.assertRaises(wd.Refused): wd.manifest_path('../other')

    def test_supervisor_pid_reuse_refuses_without_lock_or_cleanup(self):
        obj = fixture(); n02 = mock.Mock(); n02.acquire_lock.return_value = 17
        with mock.patch.object(wd, 'n02_module', return_value=n02), mock.patch.object(wd, 'safe_root'), \
             mock.patch.object(wd, 'read_protected', return_value=obj), \
             mock.patch.object(wd, 'secure_source', return_value=obj['helper_sha256']), \
             mock.patch.object(wd, 'Path') as path, mock.patch.object(wd.os.path, 'exists', return_value=True), \
             mock.patch.object(wd, 'already_completed', return_value=False), mock.patch.object(wd.os, 'close'), \
             mock.patch.object(wd, 'cleanup_owned') as cleanup:
            path.return_value.read_text.return_value = obj['boot_id']
            with self.assertRaises(wd.RetryLater): wd.recover_once(obj['run_id'])
            n02.acquire_lock.assert_called_once(); cleanup.assert_not_called()

    def test_completed_old_run_is_noop_even_if_new_run_exists(self):
        obj = fixture(); n02 = mock.Mock(); n02.acquire_lock.return_value = 17
        with mock.patch.object(wd, 'n02_module', return_value=n02), mock.patch.object(wd, 'safe_root'), \
             mock.patch.object(wd, 'read_protected', return_value=obj), \
             mock.patch.object(wd, 'secure_source', return_value=obj['helper_sha256']), \
             mock.patch.object(wd, 'Path') as path, mock.patch.object(wd, 'already_completed', return_value=True), \
             mock.patch.object(wd.os, 'close'), mock.patch.object(wd, 'cleanup_owned') as cleanup:
            path.return_value.read_text.return_value = obj['boot_id']
            wd.recover_once(obj['run_id'])
            n02.acquire_lock.assert_called_once(); cleanup.assert_not_called()

    def test_lock_contention_cannot_report_completion(self):
        obj = fixture(); n02 = mock.Mock(); n02.acquire_lock.side_effect = TimeoutError('busy')
        with mock.patch.object(wd, 'n02_module', return_value=n02), mock.patch.object(wd, 'safe_root'), \
             mock.patch.object(wd, 'read_protected', return_value=obj), \
             mock.patch.object(wd, 'secure_source', return_value=obj['helper_sha256']), \
             mock.patch.object(wd, 'Path') as path, mock.patch.object(wd, 'already_completed') as completed, \
             mock.patch.object(wd, 'cleanup_owned') as cleanup:
            path.return_value.read_text.return_value = obj['boot_id']
            with self.assertRaises(wd.RetryLater): wd.recover_once(obj['run_id'])
            completed.assert_not_called(); cleanup.assert_not_called()

    def test_retry_is_bounded_and_recovers_only_after_deferred_failure(self):
        rid = 'a'*24
        with mock.patch.object(wd, 'recover_once', side_effect=[wd.RetryLater('busy'), None]) as once, \
             mock.patch.object(wd.time, 'sleep') as sleep:
            wd.recover(rid)
            self.assertEqual(once.call_count, 2); sleep.assert_called_once_with(wd.RETRY_INTERVAL)
        with mock.patch.object(wd, 'recover_once', side_effect=wd.RetryLater('busy')) as once, \
             mock.patch.object(wd.time, 'sleep') as sleep:
            with self.assertRaises(wd.Refused): wd.recover(rid)
            self.assertEqual(once.call_count, wd.MAX_ATTEMPTS)
            self.assertEqual(sleep.call_count, wd.MAX_ATTEMPTS-1)

    def test_identity_mismatch_is_not_retried(self):
        with mock.patch.object(wd, 'recover_once', side_effect=wd.Refused('identity changed')) as once, \
             mock.patch.object(wd.time, 'sleep') as sleep:
            with self.assertRaises(wd.Refused): wd.recover('a'*24)
            once.assert_called_once(); sleep.assert_not_called()


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.obj = fixture(); self.n02 = mock.Mock()
        self.n02.NAMES = ('od-client','od-router','od-server')
        self.n02.IP = '/usr/sbin/ip'
        self.n02.helper_path.return_value = Path('/nonexistent-n01-watchdog-test')
        self.n02.load.return_value = self.obj['topology']
        self.n02.run.return_value = types.SimpleNamespace(stdout='')

    def test_unknown_private_file_stops_before_deleting_topology(self):
        with mock.patch.object(wd, 'check_private', side_effect=wd.Refused('replaced')):
            with self.assertRaises(wd.Refused): wd.cleanup_owned(self.n02, self.obj)
        self.n02.cleanup.assert_not_called()

    def test_changed_resolver_content_is_refused(self):
        obj=self.obj
        ids={'state.json':obj['state_file'],'resolv.conf':obj['resolver'],'control.sock':obj['socket']}
        stream=mock.MagicMock(); stream.__enter__.return_value=stream; stream.fileno.return_value=13
        stream.read.return_value=b'other resolver\n'
        st=types.SimpleNamespace(st_dev=1,st_ino=12,st_ctime_ns=112,st_mode=0o100600,st_uid=0,st_nlink=1)
        with mock.patch.object(wd,'file_identity',side_effect=lambda p,k:ids[p.name]), \
             mock.patch.object(wd,'read_protected',return_value=obj['state']), \
             mock.patch.object(wd.os,'open',return_value=13), mock.patch.object(wd.os,'fdopen',return_value=stream), \
             mock.patch.object(wd.os,'fstat',return_value=st), mock.patch.object(wd.os,'O_NOFOLLOW',0,create=True), \
             mock.patch.object(wd.os,'O_CLOEXEC',0,create=True), mock.patch.object(wd.os,'O_NONBLOCK',0,create=True):
            with self.assertRaises(wd.Refused): wd.check_private(obj)

    def test_new_n02_run_is_not_touched(self):
        self.n02.load.return_value = self.obj['topology'] | {'run_id':'f'*24}
        with mock.patch.object(wd, 'check_private'):
            with self.assertRaises(wd.Refused): wd.cleanup_owned(self.n02, self.obj)
        self.n02.cleanup.assert_not_called()

    def test_namespace_with_any_process_is_not_deleted(self):
        self.n02.run.return_value = types.SimpleNamespace(stdout='987\n')
        with mock.patch.object(wd, 'check_private'), mock.patch.object(wd, 'check_namespaces'):
            with self.assertRaises(wd.Refused): wd.cleanup_owned(self.n02, self.obj)
        self.n02.cleanup.assert_not_called()

    def test_namespace_replaced_is_not_deleted(self):
        with mock.patch.object(wd, 'check_private'), \
             mock.patch.object(wd, 'namespace_identity', return_value=[10,999,101]):
            with self.assertRaises(wd.Refused): wd.cleanup_owned(self.n02, self.obj)
        self.n02.cleanup.assert_not_called()

    def test_unrecorded_n02_helper_is_preserved(self):
        with mock.patch.object(wd, 'check_private'), mock.patch.object(wd, 'check_namespaces'), \
             mock.patch.object(wd.os.path, 'lexists', return_value=True):
            with self.assertRaises(wd.Refused): wd.cleanup_owned(self.n02, self.obj)
        self.n02.cleanup.assert_not_called()

    def test_wrong_rules_or_namespace_identity_stops_cleanup(self):
        for method in ('check_table','validate_owned'):
            n02 = mock.Mock(); n02.NAMES = self.n02.NAMES; n02.IP = self.n02.IP
            n02.load.return_value = self.obj['topology']
            getattr(n02, method).side_effect = wd.Refused('identity changed')
            with mock.patch.object(wd, 'check_private'):
                with self.assertRaises(wd.Refused): wd.cleanup_owned(n02, self.obj)
            n02.cleanup.assert_not_called()

    def test_matching_orphan_cleans_only_recorded_objects_then_receipt(self):
        order=[]
        self.n02.cleanup.side_effect=lambda _: order.append('n02')
        identities={'control.sock':self.obj['socket'], 'state.json':self.obj['state_file']}
        with mock.patch.object(wd, 'check_private'), mock.patch.object(wd, 'check_namespaces'), \
             mock.patch.object(wd, 'file_identity', side_effect=lambda p,kind: identities[p.name]), \
             mock.patch.object(wd, 'read_protected', return_value=self.obj['state']), \
             mock.patch.object(Path, 'unlink', autospec=True, side_effect=lambda p: order.append(p.name)), \
             mock.patch.object(wd, 'record_completion', side_effect=lambda rid: order.append('receipt:'+rid)):
            wd.cleanup_owned(self.n02, self.obj)
        self.assertEqual(order, ['n02','resolv.conf','control.sock','state.json','receipt:'+self.obj['run_id']])

    def test_new_private_state_after_topology_cleanup_is_preserved(self):
        with mock.patch.object(wd, 'check_private', side_effect=[None, wd.Refused('replaced')]), mock.patch.object(wd, 'check_namespaces'), \
             mock.patch.object(Path, 'unlink', autospec=True) as unlink, \
             mock.patch.object(wd, 'record_completion') as receipt:
            with self.assertRaises(wd.Refused): wd.cleanup_owned(self.n02, self.obj)
            self.n02.cleanup.assert_called_once()
            unlink.assert_not_called(); receipt.assert_not_called()


class TimerTests(unittest.TestCase):
    def properties(self, name):
        rid = 'a'*24; timer=wd.timer_name(rid); service=timer[:-6]+'.service'
        if name == timer:
            return {'Id':timer,'LoadState':'loaded','ActiveState':'active','SubState':'waiting',
                    'Triggers':service,'Transient':'yes','FragmentPath':'/run/systemd/transient/'+timer}
        return {'Id':service,'LoadState':'loaded','ActiveState':'inactive','Transient':'yes',
                'FragmentPath':'/run/systemd/transient/'+service,'User':'root',
                'ExecStart':'path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B '+str(wd.SELF)+' recover '+rid+' ;'}

    def test_timer_exact_identity(self):
        n02=mock.Mock(); n02.systemd_properties.side_effect=lambda name, _: self.properties(name)
        wd.verify_timer(n02,'a'*24)
        def tampered(name, _):
            result = self.properties(name)
            if name.endswith('.service'): result['ExecStart'] = 'path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /tmp/other ;'
            return result
        n02.systemd_properties.side_effect=tampered
        with self.assertRaises(wd.Refused): wd.verify_timer(n02,'a'*24)

    def test_timer_rejects_additional_execstart(self):
        n02=mock.Mock()
        def tampered(name, _):
            result = self.properties(name)
            if name.endswith('.service'):
                result['ExecStart'] += ' { path=/usr/bin/other ; argv[]=/usr/bin/other ; }'
            return result
        n02.systemd_properties.side_effect=tampered
        with self.assertRaises(wd.Refused): wd.verify_timer(n02,'a'*24)

    def test_timer_accepts_systemd_style_command_fields(self):
        n02=mock.Mock()
        def systemd_style(name, _):
            result = self.properties(name)
            if name.endswith('.service'):
                result['ExecStart'] = '{ ' + result['ExecStart'] + ' ignore_errors=no ; pid=0 ; }'
            return result
        n02.systemd_properties.side_effect=systemd_style
        wd.verify_timer(n02,'a'*24)

    def test_arm_persists_identity_before_starting_timer(self):
        obj=fixture(); n02=mock.Mock()
        n02.load.return_value=obj['topology']
        n02.systemd_properties.return_value={'LoadState':'not-found'}
        file=mock.MagicMock(); file.__enter__.return_value=file; file.fileno.return_value=44
        order=[]
        def dump(data, *args, **kwargs):
            order.append('manifest')
            self.assertEqual(data['namespace_ids'], obj['namespace_ids'])
            self.assertEqual(data['resolver'], obj['resolver'])
        with mock.patch.object(wd, 'Path') as boot_path, mock.patch.object(wd, 'safe_root'), mock.patch.object(wd, 'secure_source', return_value=obj['helper_sha256']), \
             mock.patch.object(wd, 'read_protected', return_value=obj['state']), \
             mock.patch.object(wd, 'file_identity', side_effect=lambda p,k: {'state.json':obj['state_file'], 'resolv.conf':obj['resolver'], 'control.sock':obj['socket']}[p.name]), \
             mock.patch.object(wd, 'namespace_identity', side_effect=lambda name: obj['namespace_ids'][name]), \
             mock.patch.object(wd, 'check_private'), mock.patch.object(wd.os.path, 'lexists', return_value=False), \
             mock.patch.object(wd.os, 'open', return_value=44), mock.patch.object(wd.os, 'fdopen', return_value=file), \
             mock.patch.object(wd.os, 'fsync'), mock.patch.object(wd.os, 'close'), \
             mock.patch.object(wd.os, 'O_NOFOLLOW',0,create=True), mock.patch.object(wd.os, 'O_DIRECTORY',0,create=True), \
             mock.patch.object(wd.os, 'O_CLOEXEC',0,create=True), \
             mock.patch.object(wd.json, 'dump', side_effect=dump), \
             mock.patch.object(wd.subprocess, 'run', side_effect=lambda *a,**k: order.append('timer')), \
             mock.patch.object(wd, 'verify_timer', side_effect=lambda *a: order.append('verified')):
            boot_path.return_value.read_text.return_value=obj['boot_id']
            wd.arm(n02, obj['state'], obj['topology'], obj['resolver'][:2], obj['socket'][:2])
        self.assertEqual(order, ['manifest','timer','verified'])


class ControllerIntegrationTests(unittest.TestCase):
    def test_pinned_helper_and_arm_precede_service_injection(self):
        path = Path(__file__).with_name('n01.py')
        text = path.read_text(encoding='utf-8')
        digest = hashlib.sha256(Path(__file__).with_name('n01_watchdog.py').read_bytes()).hexdigest()
        self.assertIn("WATCHDOG_SHA = '"+digest+"'", text)
        spec = importlib.util.spec_from_file_location('n01_with_watchdog', path)
        controller = importlib.util.module_from_spec(spec); spec.loader.exec_module(controller)
        n02=mock.Mock(); n02.NAMES=('od-client','od-router','od-server')
        n02.ROOT.lstat.return_value=types.SimpleNamespace(st_mode=0o40700, st_uid=0)
        n02.acquire_lock.return_value=17
        n02.setup.return_value={'run_id':'b'*24,'namespaces':{'od-server':3,'od-router':2}}
        watchdog=mock.Mock(); watchdog.arm.side_effect=wd.Refused('timer rejected')
        socket=mock.Mock()
        fdfile=mock.MagicMock(); fdfile.__enter__.return_value=fdfile
        st=types.SimpleNamespace(st_dev=1,st_ino=42,st_mode=0o100600,st_uid=0,st_nlink=1)
        # No real files, namespaces, timers, or services are started by this test.
        with mock.patch.object(controller,'n02_module',return_value=n02), mock.patch.object(controller,'root_dir'), \
             mock.patch.object(controller.os.path,'lexists',return_value=False), mock.patch.object(controller.os,'open',return_value=12), \
             mock.patch.object(controller.os,'fdopen',return_value=fdfile), mock.patch.object(controller.os,'fstat',return_value=st), \
             mock.patch.object(controller.os,'close'), mock.patch.object(controller.socket,'socket',return_value=socket), \
             mock.patch.object(controller.os,'chmod'), mock.patch.object(Path,'lstat',return_value=st), \
             mock.patch.object(controller,'atomic_state'), mock.patch.object(controller,'identity',return_value=[1,2,'python']), \
             mock.patch.object(controller,'read_state',side_effect=controller.Refused('preserve')), \
             mock.patch.object(controller,'watchdog_module',return_value=watchdog), \
             mock.patch.object(controller,'BoundedChild') as child, \
             mock.patch.object(controller.os,'O_NOFOLLOW',0,create=True), \
             mock.patch.object(controller.socket,'AF_UNIX',1,create=True):
            with self.assertRaises(wd.Refused): controller.worker()
        watchdog.arm.assert_called_once()
        child.assert_not_called()

    def test_cli_patch_pins_current_candidate_only(self):
        root=Path(__file__).parent
        digest=hashlib.sha256((root/'n01.py').read_bytes()).hexdigest()
        cli=(root.parents[2]/'scripts/opsdrill_cli.py').read_text(encoding='utf-8')
        self.assertIn("if digest!='"+digest+"':", cli)


if __name__ == '__main__': unittest.main()
