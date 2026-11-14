import contextlib
import importlib.util
import io
import json
import pathlib
import stat
import sys
import threading
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

try: import fcntl
except ImportError: sys.modules['fcntl'] = types.SimpleNamespace(LOCK_EX=1, flock=lambda *a: None)

def load(name, filename):
    spec=importlib.util.spec_from_file_location(name,pathlib.Path(__file__).resolve().parents[2] / filename)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod
m=load('c01_control_candidate','experimental/n03-c01/c01_control_v2.py')
n=load('n03_v2','experimental/n03-c01/n03_502.py')
cli=load('cli_c01','scripts/opsdrill_cli.py')
BOOT='12345678-1234-1234-1234-123456789abc'

class Node:
    def __init__(self,kind,mode=0o700): self.kind=kind; self.mode=mode; self.uid=0; self.nlink=1; self.data=bytearray(); self.children={}
class FakeOS:
    O_RDONLY=0; O_WRONLY=1; O_RDWR=2; O_DIRECTORY=4; O_NOFOLLOW=8; O_CLOEXEC=16; O_NONBLOCK=32; O_CREAT=64; O_EXCL=128
    SEEK_SET=0
    def __init__(self):
        self.root=Node('dir',0o755); self.fds={}; self.nextfd=10; self.syncs=[]; self.fail_sync=None
        node=self.root
        for part in ('var','lib','opsdrill'):
            node.children[part]=Node('dir',0o755); node=node.children[part]
    def open(self,path,flags,mode=0o777,dir_fd=None):
        if path=='/': node=self.root
        else:
            parent=self.fds[dir_fd][0]; node=parent.children.get(path)
            if node is None:
                if not flags & self.O_CREAT: raise FileNotFoundError(path)
                node=Node('file',mode); parent.children[path]=node
            elif flags & self.O_CREAT and flags & self.O_EXCL: raise FileExistsError(path)
            if node.kind=='symlink' and flags & self.O_NOFOLLOW: raise OSError('symlink')
            if flags & self.O_DIRECTORY and node.kind!='dir': raise NotADirectoryError(path)
        fd=self.nextfd; self.nextfd+=1; self.fds[fd]=[node,0]; return fd
    def close(self,fd): del self.fds[fd]
    def fstat(self,fd):
        node=self.fds[fd][0]
        typ=stat.S_IFDIR if node.kind=='dir' else stat.S_IFREG
        return types.SimpleNamespace(st_mode=typ|node.mode, st_uid=node.uid, st_nlink=node.nlink, st_size=len(node.data))
    def mkdir(self,name,mode,dir_fd):
        parent=self.fds[dir_fd][0]
        if name in parent.children: raise FileExistsError(name)
        parent.children[name]=Node('dir',mode)
    def fsync(self,fd):
        self.syncs.append(self.fds[fd][0])
        if self.fail_sync == len(self.syncs): raise OSError('simulated sync failure')
    def fchmod(self,fd,mode): self.fds[fd][0].mode=mode
    def write(self,fd,data): self.fds[fd][0].data.extend(data); return len(data)
    def read(self,fd,n):
        item=self.fds[fd]; pos=item[1]; data=bytes(item[0].data[pos:pos+n]); item[1]+=len(data); return data
    def listdir(self,fd): return list(self.fds[fd][0].children)
    def stat(self,name,dir_fd,follow_symlinks=False):
        if name not in self.fds[dir_fd][0].children: raise FileNotFoundError(name)
        return object()
    def rename(self,old,new,src_dir_fd,dst_dir_fd):
        source=self.fds[src_dir_fd][0].children; dest=self.fds[dst_dir_fd][0].children
        dest[new]=source.pop(old)
    def lseek(self,fd,pos,whence): self.fds[fd][1]=pos

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.fake=FakeOS(); self.patch=mock.patch.object(m,'os',self.fake); self.patch.start(); self.addCleanup(self.patch.stop)
        lock_patch=mock.patch.object(m.fcntl,'flock'); lock_patch.start(); self.addCleanup(lock_patch.stop)
        self.store=m.Store()
        self.receipt={'kind':'C01_APP_DOWN_V1','run_id':'a'*24,'owner_id':'b'*32,'timer':'opsdrill-n03-recover-'+'a'*24+'.timer'}
        self.record={'version':1,'receipt':self.receipt,'boot_id':BOOT}
    def test_write_and_fsync_receipt_before_backend(self):
        class Backend:
            def call(inner, action, receipt):
                self.assertEqual(action,'inject')
                with self.store.locked() as fd: self.assertEqual(self.store.current(fd)[0]['receipt'],receipt)
                self.assertTrue(len(self.fake.syncs)>=4)
                return 0, receipt
        # Fake flock is a no-op. Production relies on flock and must be tested on Linux.
        rc,out=m.Controller(self.store,Backend(),lambda:BOOT).execute('start','auto')
        self.assertEqual((rc,out['status']), (0,'FAULT_CONFIRMED'))
    def test_sync_failure_never_invokes_backend(self):
        backend=mock.Mock()
        # fail after store directory creation, during creation of current or record
        self.fake.fail_sync=3
        with self.assertRaises(OSError): m.Controller(self.store,backend,lambda:BOOT).execute('start','auto')
        backend.call.assert_not_called()
        self.fake.fail_sync=None
        with self.store.locked() as fd:
            record, done = self.store.current(fd)
            self.assertFalse(done)
            m.validate_receipt(record['receipt'])
    def test_partial_record_and_extra_file_are_fail_closed(self):
        with self.store.locked() as fd: self.store.prepare(fd,self.record)
        current=self.fake.root.children['var'].children['lib'].children['opsdrill'].children['c01'].children['current']
        current.children['unexpected']=Node('file',0o600)
        with self.store.locked() as fd:
            with self.assertRaisesRegex(m.Refused,'INCOMPLETE_STORE'): self.store.current(fd)
        current.children.pop('unexpected')
        current.children['receipt.json'].data=bytearray(b'{')
        with self.store.locked() as fd:
            with self.assertRaisesRegex(m.Refused,'INVALID_JSON'): self.store.current(fd)
    def test_symlink_and_permissions_refused(self):
        with self.store.locked() as fd: self.store.prepare(fd,self.record)
        root=self.fake.root.children['var'].children['lib'].children['opsdrill'].children['c01']
        record=root.children['current'].children['receipt.json']
        record.mode=0o644
        with self.store.locked() as fd:
            with self.assertRaisesRegex(m.Refused,'UNSAFE_RECORD'): self.store.current(fd)
        record.mode=0o600; record.kind='symlink'
        with self.store.locked() as fd:
            with self.assertRaises(OSError): self.store.current(fd)
    def test_completed_marker_archives_receipt_before_next_run(self):
        with self.store.locked() as fd:
            self.store.prepare(fd,self.record); self.store.mark_done(fd,self.record)
            self.assertEqual(self.store.current(fd),(self.record,True))
            other=dict(self.record,receipt=dict(self.receipt, run_id='c'*24, timer='opsdrill-n03-recover-'+'c'*24+'.timer'))
            self.store.prepare(fd,other)
            self.assertEqual(self.store.current(fd),(other,False))
        root=self.fake.root.children['var'].children['lib'].children['opsdrill'].children['c01']
        self.assertIn('done-'+'a'*24,root.children)
    def test_duplicate_json_keys_refused(self):
        with self.assertRaisesRegex(m.Refused,'DUPLICATE_FIELD'): m.parse(b'{"version":1,"version":1}')

class MemoryStore:
    def __init__(self): self.record=None; self.done=False; self.lock=threading.Lock()
    @contextlib.contextmanager
    def locked(self):
        with self.lock: yield 1
    def current(self,fd): return None if self.record is None else (self.record,self.done)
    def prepare(self,fd,record):
        if self.record is not None and not self.done: raise m.Refused('C01_RECEIPT_ALREADY_PRESENT')
        self.record=record; self.done=False
    def mark_done(self,fd,record):
        if self.record!=record or self.done: raise m.Refused('RECORD_CHANGED')
        self.done=True

class LifecycleTests(unittest.TestCase):
    def setUp(self): self.store=MemoryStore(); self.backend=mock.Mock(); self.controller=m.Controller(self.store,self.backend,lambda:BOOT)
    def test_interrupted_start_keeps_identity_and_blocks_next(self):
        self.backend.call.side_effect=RuntimeError('killed')
        with self.assertRaises(RuntimeError): self.controller.execute('start','auto')
        receipt=self.store.record['receipt']; m.validate_receipt(receipt)
        self.backend.call.reset_mock()
        with self.assertRaisesRegex(m.Refused,'C01_RECEIPT_ALREADY_PRESENT'): self.controller.execute('start','auto')
        self.backend.call.assert_not_called()
        _,status=self.controller.execute('status','unknown')
        self.assertEqual((status['run_id'], status['status']),(receipt['run_id'],'RECEIPT_PRESENT_UNVERIFIED'))
    def test_wrong_run_boot_missing_and_done_never_call_backend(self):
        self.backend.call.side_effect=RuntimeError()
        with self.assertRaises(RuntimeError): self.controller.execute('start','auto')
        self.backend.call.reset_mock(); rid=self.store.record['receipt']['run_id']
        for run in ('f'*24,None):
            with self.assertRaises(m.Refused): self.controller.execute('reset','auto',run)
        self.store.record['boot_id']='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        with self.assertRaisesRegex(m.Refused,'BOOT_CHANGED'): self.controller.execute('reset','auto',rid)
        self.store.done=True
        with self.assertRaisesRegex(m.Refused,'RUN_ALREADY_CLEANED'): self.controller.execute('reset','auto',rid)
        self.backend.call.assert_not_called()
    def test_reset_success_then_duplicate_refused(self):
        self.backend.call.return_value=(0,{})
        _,out=self.controller.execute('start','auto'); rid=out['run_id']
        rc,out=self.controller.execute('reset','auto',rid)
        self.assertEqual((rc,out['status']), (0,'CLEANUP_PASS'))
        self.assertTrue(self.store.done)
        self.backend.call.reset_mock()
        with self.assertRaisesRegex(m.Refused,'RUN_ALREADY_CLEANED'): self.controller.execute('reset','auto',rid)
        self.backend.call.assert_not_called()
    def test_failed_reset_keeps_receipt_and_no_done(self):
        self.backend.call.return_value=(0,{})
        _,out=self.controller.execute('start','auto'); rid=out['run_id']
        self.backend.call.side_effect=m.Refused('N03_REFUSED_OR_FAILED')
        with self.assertRaises(m.Refused): self.controller.execute('reset','auto',rid)
        self.assertFalse(self.store.done); self.assertEqual(self.store.record['receipt']['run_id'],rid)
    def test_check_never_reports_full_success(self):
        self.backend.call.return_value=(0,{})
        _,out=self.controller.execute('start','auto'); rid=out['run_id']
        rc,out=self.controller.execute('check','auto',rid)
        self.assertEqual((rc,out['status'],out['overall']), (2,'RECOVERED_PARTIAL','INCOMPLETE'))
    def test_concurrent_start_only_one_backend_call(self):
        gate=threading.Barrier(2)
        self.backend.call.return_value=(0,{})
        def attempt(i):
            gate.wait()
            try: return self.controller.execute('start','auto')[0]
            except m.Refused: return 2
        with ThreadPoolExecutor(max_workers=2) as ex: values=list(ex.map(attempt,range(2)))
        self.assertCountEqual(values,[0,2]); self.assertEqual(self.backend.call.call_count,1)

class BackendTests(unittest.TestCase):
    def setUp(self):
        self.receipt={'kind':'C01_APP_DOWN_V1','run_id':'a'*24,'owner_id':'b'*32,'timer':'opsdrill-n03-recover-'+'a'*24+'.timer'}
    def call(self,action,rc,data):
        cp=types.SimpleNamespace(returncode=rc,stdout=data)
        with mock.patch.object(m,'secure_n03_fd',return_value=17), mock.patch.object(m.os,'close'), mock.patch.object(m.subprocess,'run',return_value=cp) as run:
            result=m.N03Backend().call(action,self.receipt)
            self.assertEqual(run.call_args.args[0][-3:], ['c01-'+action, self.receipt['run_id'], self.receipt['owner_id']])
            self.assertEqual(run.call_args.kwargs['pass_fds'], (17,))
            return result
    def test_check_formats_and_exit_codes(self):
        self.assertEqual(self.call('check',1,b'{"status":"FAULT_PRESENT","nginx_status":502}')[0],1)
        self.assertEqual(self.call('check',0,b'{"status":"RECOVERED","health":200,"ready":200}')[0],0)
        for rc,data in [(0,b'{"status":"FAULT_PRESENT","nginx_status":502}'),(1,b'{}'),(2,b'{}')]:
            with self.assertRaises(m.Refused): self.call('check',rc,data)
    def test_receipt_and_reset_must_match(self):
        self.assertEqual(self.call('inject',0,json.dumps(self.receipt).encode())[1],self.receipt)
        with self.assertRaises(m.Refused): self.call('inject',0,b'{}')
        with self.assertRaises(m.Refused): self.call('reset',0,b'{"status":"CLEANUP_PASS","run_id":"wrong","service_action":"STARTED"}')
    def test_owner_validation_precedes_subprocess(self):
        with mock.patch.object(m,'secure_n03_fd') as fd:
            with self.assertRaises(m.Refused): m.N03Backend().call('reset',dict(self.receipt,owner_id='bad'))
            fd.assert_not_called()

class N03AndCLITests(unittest.TestCase):
    def test_unconfirmed_fault_refuses_before_service_read(self):
        rid='a'*24; owner='b'*32
        state={'kind':'n03-502','run_id':rid,'phase':'WATCHDOG_HEALTHY','timer':'opsdrill-n03-recover-'+rid+'.timer',
               'owner_kind':'C01_APP_DOWN_V1','owner_id':owner}
        with mock.patch.object(n,'guard'), mock.patch.object(n,'locked',return_value=contextlib.nullcontext(1)), \
             mock.patch.object(n,'read_state',return_value=state), mock.patch.object(n,'service_identity') as service:
            with self.assertRaisesRegex(n.Refused,'C01_FAULT_NOT_CONFIRMED'): n.check(rid,(rid,owner))
            service.assert_not_called()
    def test_confirmed_fault_needs_helper_and_unambiguous_dead_service(self):
        rid='a'*24; owner='b'*32
        state={'kind':'n03-502','run_id':rid,'phase':'FAULT','timer':'opsdrill-n03-recover-'+rid+'.timer',
               'owner_kind':'C01_APP_DOWN_V1','owner_id':owner, 'c01_fault_confirmed':True, 'service_sha':'c'*64}
        service={'ActiveState':'inactive','SubState':'dead','MainPID':'0'}
        with mock.patch.object(n,'guard'), mock.patch.object(n,'locked',return_value=contextlib.nullcontext(1)), \
             mock.patch.object(n,'read_state',return_value=state), mock.patch.object(n,'helper_verified') as helper, \
             mock.patch.object(n,'service_identity',return_value=(service,'c'*64)), \
             mock.patch.object(n,'request',return_value=(502,None)), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(n.check(rid,(rid,owner)),1)
            helper.assert_called_once_with(state)
            service['MainPID']='123'
            with self.assertRaisesRegex(n.Refused,'SERVICE_STATE_AMBIGUOUS'): n.check(rid,(rid,owner))

    def test_cli_dispatch_and_required_expected_id(self):
        args=types.SimpleNamespace(drill='C01',command='reset',expect_run_id='a'*24)
        with mock.patch.object(cli,'require_root'), mock.patch.object(cli,'safe_dir'), mock.patch.object(cli,'open_lock',return_value=3), \
             mock.patch.object(cli.os,'close'), mock.patch.object(cli,'c01_call',return_value=types.SimpleNamespace(returncode=0)) as command, \
             mock.patch.object(cli,'read_state',return_value=None) as read:
            self.assertEqual(cli.action(args),0); command.assert_called_once_with('reset','auto','a'*24); read.assert_called_once_with('C01')
            args.expect_run_id=None
            with self.assertRaises(cli.Refused): cli.action(args)
            self.assertEqual(command.call_count,1)


class PinnedFilesTests(unittest.TestCase):
    def setUp(self):
        self.fake=FakeOS()
        node=self.fake.root
        for part in ('usr','local','libexec','opsdrill','n03'):
            node.children[part]=Node('dir',0o755); node=node.children[part]
        self.n03=node.children['n03_502.py']=Node('file',0o600)
        self.n03.data=bytearray((pathlib.Path(__file__).resolve().parents[2] / 'experimental/n03-c01/n03_502.py').read_bytes())
        node=self.fake.root
        for part in ('usr','local','libexec','opsdrill'):
            node=node.children[part]
        node.children['c01-v2']=Node('dir',0o755)
        node=node.children['c01-v2']
        self.control=node.children['c01_control.py']=Node('file',0o600)
        self.control.data=bytearray((pathlib.Path(__file__).resolve().parents[2] / 'experimental/n03-c01/c01_control_v2.py').read_bytes())

    def test_n03_digest_and_permissions_are_enforced(self):
        with mock.patch.object(m,'os',self.fake):
            fd=m.secure_n03_fd(); self.fake.close(fd)
            self.n03.data.extend(b'x')
            with self.assertRaisesRegex(m.Refused,'N03_DIGEST_MISMATCH'): m.secure_n03_fd()
            self.n03.data.pop(); self.n03.mode=0o666
            with self.assertRaisesRegex(m.Refused,'UNSAFE_N03'): m.secure_n03_fd()

    def test_cli_controller_digest_is_enforced_before_execute(self):
        cp=types.SimpleNamespace(returncode=0)
        with mock.patch.object(cli,'os',self.fake), mock.patch.object(cli.subprocess,'run',return_value=cp) as run:
            self.assertEqual(cli.c01_call('status','unknown').returncode,0)
            self.assertEqual(run.call_count,1)
            self.control.data.extend(b'x')
            with self.assertRaisesRegex(cli.Refused,'version mismatch'): cli.c01_call('status','unknown')
            self.assertEqual(run.call_count,1)

    def test_every_presubmit_fsync_failure_prevents_injection(self):
        for point in range(1,6):
            with self.subTest(fsync=point):
                fake=FakeOS(); fake.fail_sync=point; backend=mock.Mock()
                with mock.patch.object(m,'os',fake):
                    with self.assertRaises(OSError): m.Controller(m.Store(),backend,lambda:BOOT).execute('start','auto')
                backend.call.assert_not_called()

if __name__=='__main__': unittest.main(verbosity=2)
