"""Offline-only tests: do not call systemctl or write to /mnt/opsdrill."""
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

FILE=Path(__file__).resolve().parents[2]/'drills/linux/L03/l03_control.py'
spec=importlib.util.spec_from_file_location('l03_control',str(FILE))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def unit_props(rid, **overrides):
    unit='opsdrill-l03-'+rid+'.service'
    argv=f'/usr/bin/python3 {m.CODE} worker {rid}'
    props={
        'LoadState':'loaded',
        'ExecStart':f'{{ path=/usr/bin/python3 ; argv[]={argv} ; ignore_errors=no ; start_time=[0] ; stop_time=[0] ; pid=123 ; code=(null) ; status=0/0 }}',
        'FragmentPath':'/run/systemd/transient/'+unit,
        'ControlGroup':'/system.slice/'+unit,
        'Type':'exec','User':'','Group':'','InvocationID':'a'*32,
    }
    props.update(overrides)
    return props


class Offline(unittest.TestCase):
    def test_limits(self):
        self.assertEqual(m.WRITE_MIB,64)
        self.assertEqual(m.READ_PASSES,4)
        self.assertEqual(m.MAX_SEC,30)
        self.assertEqual(m.FREE_MIN,5*1024**3)
    def test_run_id_restriction(self):
        self.assertIsNotNone(m.RUN_ID.fullmatch('a'*24))
        for x in ('../a','b'*23,'z'*24,'a'*25):
            self.assertIsNone(m.RUN_ID.fullmatch(x))
    def test_unit_name_restriction(self):
        self.assertIsNotNone(m.UNIT_RE.fullmatch('opsdrill-l03-'+'a'*24+'.service'))
        self.assertIsNone(m.UNIT_RE.fullmatch('other.service'))
    def test_unit_valid(self):
        rid='a'*24; unit='opsdrill-l03-'+rid+'.service'
        self.assertTrue(m.verify_unit(unit,rid,unit_props(rid)))
    def test_unit_wrong_exec_rejected(self):
        rid='a'*24;unit='opsdrill-l03-'+rid+'.service'
        props=unit_props(rid, ExecStart=f'{{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /bin/false worker {rid} ; ignore_errors=no }}')
        with self.assertRaisesRegex(m.Unsafe,'UNIT_EXEC_MISMATCH'):
            m.verify_unit(unit,rid,props)
    def test_unit_extra_argv_rejected(self):
        rid='a'*24;unit='opsdrill-l03-'+rid+'.service'
        props=unit_props(rid, ExecStart=f'{{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 {m.CODE} worker {rid} --extra ; ignore_errors=no }}')
        with self.assertRaisesRegex(m.Unsafe,'UNIT_EXEC_MISMATCH'):
            m.verify_unit(unit,rid,props)
    def test_unit_substring_only_not_accepted(self):
        rid='a'*24;unit='opsdrill-l03-'+rid+'.service'
        props=unit_props(rid, ExecStart=f'{{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 {m.CODE}.attacker worker {rid} ; ignore_errors=no }}')
        with self.assertRaisesRegex(m.Unsafe,'UNIT_EXEC_MISMATCH'):
            m.verify_unit(unit,rid,props)
    def test_unit_wrong_fragment_rejected(self):
        rid='a'*24;unit='opsdrill-l03-'+rid+'.service'
        with self.assertRaisesRegex(m.Unsafe,'UNIT_FRAGMENT_MISMATCH'):
            m.verify_unit(unit,rid,unit_props(rid, FragmentPath='/etc/systemd/system/'+unit))
    def test_unit_wrong_type_rejected(self):
        rid='a'*24;unit='opsdrill-l03-'+rid+'.service'
        with self.assertRaisesRegex(m.Unsafe,'UNIT_TYPE_MISMATCH'):
            m.verify_unit(unit,rid,unit_props(rid, Type='simple'))
    def test_unit_wrong_user_rejected(self):
        rid='a'*24;unit='opsdrill-l03-'+rid+'.service'
        with self.assertRaisesRegex(m.Unsafe,'UNIT_USER_MISMATCH'):
            m.verify_unit(unit,rid,unit_props(rid, User='nobody'))
    def test_unit_wrong_cgroup_rejected(self):
        rid='a'*24;unit='opsdrill-l03-'+rid+'.service'
        props=unit_props(rid, ControlGroup='/system.slice/other.service')
        with self.assertRaisesRegex(m.Unsafe,'UNIT_CGROUP_MISMATCH'):
            m.verify_unit(unit,rid,props)
    def test_unit_not_found(self):
        rid='a'*24;self.assertFalse(m.verify_unit('opsdrill-l03-'+rid+'.service',rid,{'LoadState':'not-found'}))
    def test_state_invalid_run_id(self):
        with tempfile.TemporaryDirectory() as p:
            os.mkdir(os.path.join(p,'runs'),0o700)
            rfd=m.open_dir(p);runs=m.open_dir('runs',rfd)
            try:
                with self.assertRaisesRegex(m.Unsafe,'STATE_RUN_ID'):
                    m.state_valid({'version':1,'run_id':'../../tmp'},rfd,runs)
            finally:os.close(runs);os.close(rfd)
    def test_state_valid_identity(self):
        with tempfile.TemporaryDirectory() as p:
            os.mkdir(os.path.join(p,'runs'),0o700)
            rid='a'*24;os.mkdir(os.path.join(p,'runs',rid),0o700)
            root=m.open_dir(p);runs=m.open_dir('runs',root);run=m.open_dir(rid,runs)
            try:
                st=os.fstat(root); t=os.fstat(run)
                s={'version':2,'run_id':rid,'unit':'opsdrill-l03-'+rid+'.service',
                   'root_dev':st.st_dev,'root_ino':st.st_ino,'run_dev':t.st_dev,'run_ino':t.st_ino,
                   'exec_argv':m.expected_argv(rid),'status':'STARTED'}
                self.assertEqual(m.state_valid(s,root,runs),rid)
                s['run_ino']+=1
                with self.assertRaisesRegex(m.Unsafe,'RUN_REPLACED'):m.state_valid(s,root,runs)
            finally:os.close(run);os.close(runs);os.close(root)
    def test_reset_run_id_mismatch_refuses_other_run(self):
        with tempfile.TemporaryDirectory() as p:
            (Path(p)/'runs').mkdir(mode=0o700)
            rid='d'*24; other='e'*24
            (Path(p)/'runs'/rid).mkdir(mode=0o700)
            root=m.open_dir(p);runs=m.open_dir('runs',root);run=m.open_dir(rid,runs)
            try:
                rst=os.fstat(root);dst=os.fstat(run)
                state={'version':2,'run_id':rid,'unit':'opsdrill-l03-'+rid+'.service',
                       'root_dev':rst.st_dev,'root_ino':rst.st_ino,'run_dev':dst.st_dev,'run_ino':dst.st_ino,
                       'exec_argv':m.expected_argv(rid),'status':'STARTED'}
                m.atomic_json(root,m.STATE,state)
            finally: os.close(run)
            try:
                with patch.object(m,'check_lab'), patch.object(m,'existing_root',return_value=(root,runs)):
                    with self.assertRaisesRegex(m.Unsafe,'RESET_RUN_ID_MISMATCH'):
                        m.reset(other,'opsdrill-l03-'+other+'.service')
                self.assertTrue((Path(p)/m.STATE).exists())
                self.assertTrue((Path(p)/'runs'/rid).is_dir())
            finally:
                # reset() owns and closes these descriptors even on rejection.
                pass

    def test_state_exec_argv_mismatch(self):
        with tempfile.TemporaryDirectory() as p:
            os.mkdir(os.path.join(p,'runs'),0o700)
            rid='a'*24;os.mkdir(os.path.join(p,'runs',rid),0o700)
            root=m.open_dir(p);runs=m.open_dir('runs',root)
            try:
                st=os.fstat(root); run=os.open(rid,os.O_RDONLY|os.O_DIRECTORY,dir_fd=runs)
                try: rst=os.fstat(run)
                finally: os.close(run)
                state={'version':2,'run_id':rid,'unit':'opsdrill-l03-'+rid+'.service',
                       'root_dev':st.st_dev,'root_ino':st.st_ino,'run_dev':rst.st_dev,'run_ino':rst.st_ino,
                       'exec_argv':[m.PYTHON,m.CODE,'worker',rid,'--extra'],'status':'STARTED'}
                with self.assertRaisesRegex(m.Unsafe,'STATE_EXEC_ARGV'):
                    m.state_valid(state,root,runs)
            finally: os.close(runs);os.close(root)

    def test_atomic_json(self):
        with tempfile.TemporaryDirectory() as p:
            d=m.open_dir(p)
            try:
                m.atomic_json(d,'state.json',{'status':'ok'})
                self.assertEqual(m.read_json(d,'state.json'),{'status':'ok'})
                self.assertEqual(stat.S_IMODE(os.stat('state.json',dir_fd=d).st_mode),0o600)
            finally:os.close(d)
    def test_symlink_json_rejected(self):
        with tempfile.TemporaryDirectory() as p:
            d=m.open_dir(p)
            try:
                os.symlink('/etc/passwd',os.path.join(p,'evil'))
                with self.assertRaises(OSError):m.read_json(d,'evil')
            finally:os.close(d)
    def test_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as p:
            d=m.open_dir(p)
            try:
                Path(p,'a').write_text('x');os.chmod(Path(p,'a'),0o600);os.link(Path(p,'a'),Path(p,'b'))
                with self.assertRaisesRegex(m.Unsafe,'FILE_UNSAFE'):
                    m.safe_unlink(d,'a')
            finally:os.close(d)
    def test_unexpected_inode_rejected(self):
        with tempfile.TemporaryDirectory() as p:
            d=m.open_dir(p)
            try:
                Path(p,'a').write_text('x');os.chmod(Path(p,'a'),0o600)
                with self.assertRaisesRegex(m.Unsafe,'FILE_REPLACED'):m.safe_unlink(d,'a',[0,0])
            finally:os.close(d)
    def test_directory_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as p:
            os.symlink('/tmp',Path(p,'link'))
            d=m.open_dir(p)
            try:
                with self.assertRaises(OSError):m.open_dir('link',d)
            finally:os.close(d)
    def test_directory_world_writable_rejected(self):
        with tempfile.TemporaryDirectory() as p:
            os.mkdir(Path(p,'bad'),0o777);os.chmod(Path(p,'bad'),0o777)
            d=m.open_dir(p)
            try:
                with self.assertRaisesRegex(m.Unsafe,'DIR_PERMISSIONS'):m.open_dir('bad',d)
            finally:os.close(d)
    def _cleanup_tree(self, payload=True, identity=True):
        td=tempfile.TemporaryDirectory()
        root_path=Path(td.name)
        (root_path/'runs').mkdir(mode=0o700)
        rid='b'*24
        (root_path/'runs'/rid).mkdir(mode=0o700)
        root=m.open_dir(td.name);runs=m.open_dir('runs',root);dfd=m.open_dir(rid,runs)
        payload_id=None
        if payload:
            fd=os.open('payload.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dfd)
            try:
                os.write(fd,b'payload')
                st=os.fstat(fd)
            finally: os.close(fd)
            rst=os.fstat(root);dst=os.fstat(dfd)
            payload_id={'version':1,'run_id':rid,'root_dev':rst.st_dev,'root_ino':rst.st_ino,
                        'run_dev':dst.st_dev,'run_ino':dst.st_ino,
                        'payload_dev':st.st_dev,'payload_ino':st.st_ino}
            if identity:
                m.exclusive_json(dfd,'payload.identity.json',payload_id)
        return td,root,runs,dfd,rid,payload_id

    def test_reset_payload_without_result_uses_independent_identity(self):
        td,root,runs,dfd,rid,payload_id=self._cleanup_tree(payload=True,identity=True)
        try:
            m.cleanup_run_files(root,dfd,rid,None)
            self.assertEqual(os.listdir(dfd),[])
        finally: os.close(dfd);os.close(runs);os.close(root);td.cleanup()

    def test_reset_missing_result_and_identity_refuses_payload(self):
        td,root,runs,dfd,rid,payload_id=self._cleanup_tree(payload=True,identity=False)
        try:
            with self.assertRaisesRegex(m.Unsafe,'PAYLOAD_IDENTITY_MISSING'):
                m.cleanup_run_files(root,dfd,rid,None)
            self.assertIn('payload.bin',os.listdir(dfd))
        finally: os.close(dfd);os.close(runs);os.close(root);td.cleanup()

    def test_reset_identity_inode_mismatch_refuses_payload(self):
        td,root,runs,dfd,rid,payload_id=self._cleanup_tree(payload=True,identity=True)
        try:
            payload_id['payload_ino'] += 1
            # Replace the identity record only inside the isolated test fixture.
            m.atomic_json(dfd,'payload.identity.json',payload_id)
            with self.assertRaisesRegex(m.Unsafe,'PAYLOAD_IDENTITY_MISMATCH'):
                m.cleanup_run_files(root,dfd,rid,None)
            self.assertIn('payload.bin',os.listdir(dfd))
        finally: os.close(dfd);os.close(runs);os.close(root);td.cleanup()

    def test_reset_identity_for_wrong_run_refuses_payload(self):
        td,root,runs,dfd,rid,payload_id=self._cleanup_tree(payload=True,identity=True)
        try:
            payload_id['run_id']='c'*24
            m.atomic_json(dfd,'payload.identity.json',payload_id)
            with self.assertRaisesRegex(m.Unsafe,'PAYLOAD_IDENTITY_RUN_ID'):
                m.cleanup_run_files(root,dfd,rid,None)
            self.assertIn('payload.bin',os.listdir(dfd))
        finally: os.close(dfd);os.close(runs);os.close(root);td.cleanup()

    def test_reset_identity_without_payload_refuses(self):
        td,root,runs,dfd,rid,payload_id=self._cleanup_tree(payload=True,identity=True)
        try:
            os.unlink('payload.bin',dir_fd=dfd)
            with self.assertRaisesRegex(m.Unsafe,'PAYLOAD_MISSING_WITH_IDENTITY'):
                m.cleanup_run_files(root,dfd,rid,None)
            self.assertIn('payload.identity.json',os.listdir(dfd))
        finally: os.close(dfd);os.close(runs);os.close(root);td.cleanup()

    def test_reset_result_identity_mismatch_refuses_before_unlink(self):
        td,root,runs,dfd,rid,payload_id=self._cleanup_tree(payload=True,identity=True)
        try:
            with self.assertRaisesRegex(m.Unsafe,'RESULT_PAYLOAD_IDENTITY_MISMATCH'):
                m.cleanup_run_files(root,dfd,rid,{'payload_identity':[1,2]})
            self.assertIn('payload.bin',os.listdir(dfd))
            self.assertIn('payload.identity.json',os.listdir(dfd))
        finally: os.close(dfd);os.close(runs);os.close(root);td.cleanup()

    def test_safe_unlink_payload_requires_identity(self):
        td,root,runs,dfd,rid,payload_id=self._cleanup_tree(payload=True,identity=False)
        try:
            with self.assertRaisesRegex(m.Unsafe,'PAYLOAD_IDENTITY_REQUIRED'):
                m.safe_unlink(dfd,'payload.bin')
            self.assertIn('payload.bin',os.listdir(dfd))
        finally: os.close(dfd);os.close(runs);os.close(root);td.cleanup()

    def test_health_failure(self):
        with patch.object(m.urllib.request,'urlopen',side_effect=OSError('offline')):
            self.assertFalse(m.health())
    def test_check_lab_reject_nonroot(self):
        with patch.object(m.os,'geteuid',return_value=1000):
            with self.assertRaisesRegex(m.Unsafe,'ROOT_REQUIRED'):m.check_lab()
    def test_no_arbitrary_commands(self):
        with self.assertRaisesRegex(m.Unsafe,'BAD_ARGS'):m.main(['prog','rm','/'])
    def test_active_set(self):
        self.assertTrue(m.active({'ActiveState':'deactivating'}))
        self.assertFalse(m.active({'ActiveState':'failed'}))
    def test_json_corruption_fails_closed(self):
        with tempfile.TemporaryDirectory() as p:
            d=m.open_dir(p)
            try:
                Path(p,'x').write_text('broken');os.chmod(Path(p,'x'),0o600)
                with self.assertRaises(json.JSONDecodeError):m.read_json(d,'x')
            finally:os.close(d)

if __name__=='__main__':unittest.main()
