import importlib.util
import json
import os
import tempfile
import unittest
import contextlib
import types
from pathlib import Path
from unittest import mock

source = Path(__file__).with_name('l01_control.py')
if not source.exists():
    source = Path(__file__).resolve().parents[2] / 'drills/linux/L01/l01_control.py'
spec = importlib.util.spec_from_file_location('l01', source)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SafetyTests(unittest.TestCase):
    def setUp(self):
        owner = mock.patch.object(m, 'OWNER', os.geteuid())
        owner.start()
        self.addCleanup(owner.stop)

    def test_check_requires_at_least_ten_percent_free_inodes(self):
        state = {'phase': 'FAULT'}
        with mock.patch.object(m, 'guard'), mock.patch.object(m.os.path, 'lexists', return_value=True), \
             mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), \
             mock.patch.object(m, 'run_path', return_value=Path('/fake')), \
             mock.patch.object(m, 'verify_mount', return_value=(None, Path('/fake/mount'), True)), \
             mock.patch.object(m, 'check_contents'), mock.patch.object(m, 'probe_writable') as probe, \
             mock.patch.object(m, 'verify_logrotate') as policy, \
             mock.patch.object(m.os, 'statvfs') as statvfs:
            statvfs.return_value = types.SimpleNamespace(f_ffree=99, f_files=1000)
            self.assertEqual(m.check(), 1)
            statvfs.return_value = types.SimpleNamespace(f_ffree=100, f_files=1000)
            self.assertEqual(m.check(), 0)
            probe.assert_called_once()
            policy.assert_called_once()

    def test_write_probe_cleans_up_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            mount = Path(d)
            existing = mount / 'inode-1024'
            existing.write_text('preserve')
            m.probe_writable(mount)
            self.assertEqual(existing.read_text(), 'preserve')
            self.assertEqual(sorted(p.name for p in mount.iterdir()), ['inode-1024'])

    def test_recovery_refuses_bad_rotation_policy(self):
        state = {'phase': 'FAULT'}
        with mock.patch.object(m, 'guard'), mock.patch.object(m.os.path, 'lexists', return_value=True), \
             mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), \
             mock.patch.object(m, 'run_path', return_value=Path('/fake')), \
             mock.patch.object(m, 'verify_mount', return_value=(None, Path('/fake/mount'), True)), \
             mock.patch.object(m, 'check_contents'), mock.patch.object(m, 'probe_writable'), \
             mock.patch.object(m, 'verify_logrotate', side_effect=m.Refused('BAD_POLICY')), \
             mock.patch.object(m.os, 'statvfs', return_value=types.SimpleNamespace(f_ffree=100, f_files=1000)):
            with self.assertRaisesRegex(m.Refused, 'BAD_POLICY'):
                m.check()

    def test_mount_contents_refuse_unknown_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'inode-0000').touch(mode=0o600)
            m.check_contents(root)
            (root / 'unexpected').touch()
            with self.assertRaises(m.Refused):
                m.check_contents(root)
            (root / 'unexpected').unlink()
            (root / 'inode-0001').symlink_to(root / 'inode-0000')
            with self.assertRaises(m.Refused):
                m.check_contents(root)

    def test_mount_contents_refuse_hardlink_and_nonempty_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root / 'inode-0000'
            p.write_bytes(b'x')
            with self.assertRaises(m.Refused):
                m.check_contents(root)
            p.write_bytes(b'')
            os.link(p, root / 'inode-0001')
            with self.assertRaises(m.Refused):
                m.check_contents(root)

    def test_reset_refuses_unrecognized_run_contents_before_unmount(self):
        with tempfile.TemporaryDirectory() as d:
            run = Path(d)
            (run / 'foreign').touch()
            with mock.patch.object(m, 'run_path', return_value=run), \
                 mock.patch.object(m, 'command') as command:
                with self.assertRaises(m.Refused):
                    m.reset_locked(-1, {})
                command.assert_not_called()

    def test_expected_run_id_is_required_before_reset(self):
        state = {'run_id': 'a' * 24}
        with mock.patch.object(m, 'guard'), mock.patch.object(m.os.path, 'lexists', return_value=True), \
             mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), mock.patch.object(m, 'reset_locked') as reset:
            with self.assertRaisesRegex(m.Refused, 'RUN_ID_MISMATCH'):
                m.reset('b' * 24)
            reset.assert_not_called()

    def test_reset_after_detach_does_not_touch_reused_loop(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            run = root / 'run'
            run.mkdir()
            (run / 'mount').mkdir()
            image = run / 'disk.img'
            image.touch()
            (root / m.STATE).touch()
            dfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(m, 'run_path', return_value=run), \
                     mock.patch.object(m, 'image_identity', return_value=image), \
                     mock.patch.object(m, 'mount_source', return_value=None), \
                     mock.patch.object(m, 'loop_backing') as backing, \
                     mock.patch.object(m, 'command', return_value='') as command:
                    m.reset_locked(dfd, {'loop': '/dev/loop2', 'loop_rdev': 12})
                    backing.assert_not_called()
                    self.assertEqual(len(command.call_args_list), 1)
                    self.assertFalse(run.exists())
            finally:
                os.close(dfd)

    def test_reset_refuses_image_attached_to_different_loop(self):
        with tempfile.TemporaryDirectory() as d:
            run = Path(d)
            (run / 'mount').mkdir()
            image = run / 'disk.img'
            image.touch()
            with mock.patch.object(m, 'run_path', return_value=run), \
                 mock.patch.object(m, 'image_identity', return_value=image), \
                 mock.patch.object(m, 'mount_source', return_value=None), \
                 mock.patch.object(m, 'command', return_value='/dev/loop7') as command:
                with self.assertRaisesRegex(m.Refused, 'UNEXPECTED_LOOP_ATTACHMENT'):
                    m.reset_locked(-1, {'loop': '/dev/loop2', 'loop_rdev': 12})
                self.assertEqual(len(command.call_args_list), 1)
                self.assertTrue(image.exists())

    def test_mount_rejects_wrong_device_before_unmount(self):
        with tempfile.TemporaryDirectory() as d:
            run = Path(d)
            (run / 'mount').mkdir()
            state = {'loop': '/dev/loop2', 'loop_rdev': 12}
            with mock.patch.object(m, 'image_identity', return_value=run / 'disk.img'), \
                 mock.patch.object(m, 'loop_backing', return_value=13):
                with self.assertRaisesRegex(m.Refused, 'LOOP_DEVICE_CHANGED'):
                    m.verify_mount(state, run)

    def test_state_rejects_invalid_id_phase_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            dfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                state = {'version': 1, 'mode': 'inode', 'run_id': '../escape', 'phase': 'FAULT'}
                path = root / m.STATE
                path.write_text(json.dumps(state))
                path.chmod(0o600)
                with self.assertRaises(m.Refused):
                    m.read_state(dfd)
                state['run_id'] = 'a' * 24
                state['phase'] = 'UNKNOWN'
                path.write_text(json.dumps(state))
                with self.assertRaises(m.Refused):
                    m.read_state(dfd)
                path.unlink()
                path.symlink_to('/etc/passwd')
                with self.assertRaises(OSError):
                    m.read_state(dfd)
            finally:
                os.close(dfd)


if __name__ == '__main__':
    unittest.main(verbosity=2)
