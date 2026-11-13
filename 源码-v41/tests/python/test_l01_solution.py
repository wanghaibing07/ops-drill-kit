import contextlib
import importlib.util
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

root = pathlib.Path(__file__).resolve().parents[2]
source = root / 'tests/solutions/L01/solution.py'
spec = importlib.util.spec_from_file_location('l01_solution', source)
solution = importlib.util.module_from_spec(spec)
spec.loader.exec_module(solution)


@unittest.skipUnless(hasattr(solution.os, 'geteuid') and solution.os.geteuid() == 0,
                     'owned file tests require root')
class SolutionSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mount = pathlib.Path(self.tmp.name) / 'mount'
        self.mount.mkdir()
        self.rid = 'a' * 24
        self.state = {'run_id': self.rid, 'phase': 'FAULT'}
        patches = [
            mock.patch.object(solution.m, 'guard'),
            mock.patch.object(solution.m, 'locked', return_value=contextlib.nullcontext(7)),
            mock.patch.object(solution.m, 'read_state', return_value=self.state),
            mock.patch.object(solution.m, 'run_path', return_value=self.mount),
            mock.patch.object(solution.m, 'verify_mount', return_value=(None, self.mount, True)),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_wrong_run_never_removes_files(self):
        owned = self.mount / 'inode-0000'
        owned.touch()
        with self.assertRaisesRegex(solution.m.Refused, 'RUN_ID_MISMATCH'):
            solution.resolve('inode', 'b' * 24)
        self.assertTrue(owned.exists())

    def test_unknown_symlink_refuses_before_any_removal(self):
        owned = self.mount / 'inode-0000'
        owned.touch()
        target = pathlib.Path(self.tmp.name) / 'unrelated'
        target.write_text('preserve', encoding='utf-8')
        (self.mount / 'inode-0001').symlink_to(target)
        with self.assertRaisesRegex(solution.m.Refused, 'UNKNOWN_MOUNT_CONTENT'):
            solution.resolve('inode', self.rid)
        self.assertTrue(owned.exists())
        self.assertEqual(target.read_text(encoding='utf-8'), 'preserve')

    def test_removes_only_as_many_owned_empty_files_as_needed(self):
        for index in range(3):
            (self.mount / ('inode-%04d' % index)).touch()
        def counts(_path):
            files = list(self.mount.glob('inode-*'))
            return SimpleNamespace(f_files=10, f_ffree=3-len(files))
        with mock.patch.object(solution.os, 'statvfs', side_effect=counts):
            result = solution.resolve('inode', self.rid)
        self.assertEqual(result['removed_empty_files'], 1)
        self.assertEqual(len(list(self.mount.glob('inode-*'))), 2)

    def test_foreign_unit_is_never_stopped(self):
        with mock.patch.object(solution.deleted, 'stop_unit') as stop:
            with self.assertRaisesRegex(solution.m.Refused, 'BAD_UNIT'):
                solution.resolve('deleted-open', self.rid, 'unrelated.service')
            stop.assert_not_called()

    def test_missing_owned_holder_does_not_stop_unit(self):
        unit = solution.deleted.expected_unit(self.rid)
        state = dict(self.state, variant='deleted-open', unit=unit, payload_dev=1, payload_ino=2)
        with mock.patch.object(solution.m, 'read_state', return_value=state), \
             mock.patch.object(solution.deleted, 'state_with_unit', return_value=state), \
             mock.patch.object(solution.deleted, 'properties', return_value={}), \
             mock.patch.object(solution.deleted, 'verify_unit'), \
             mock.patch.object(solution.deleted, 'open_deleted_refs', return_value=0), \
             mock.patch.object(solution.deleted, 'stop_unit') as stop:
            with self.assertRaisesRegex(solution.m.Refused, 'NO_OWNED_HOLDER'):
                solution.resolve('deleted-open', self.rid, unit)
            stop.assert_not_called()


if __name__ == '__main__':
    unittest.main()
