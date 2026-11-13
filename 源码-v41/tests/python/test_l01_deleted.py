import importlib.util
import os
import sys
import types
import tempfile
import unittest
from pathlib import Path
from unittest import mock

source = Path(__file__).resolve().parent
if not (source / 'l01_deleted.py').exists():
    source = Path(__file__).resolve().parents[2] / 'drills/linux/L01'
sys.path.insert(0, str(source))
import l01_deleted as d


class DeletedOpenTests(unittest.TestCase):
    def setUp(self):
        self.rid = 'a' * 24
        self.unit = d.expected_unit(self.rid)
        self.props = {
            'LoadState': 'loaded', 'ActiveState': 'active', 'Type': 'exec',
            'FragmentPath': '/run/systemd/transient/' + self.unit,
            'ControlGroup': '/system.slice/' + self.unit,
            'ExecStart': '{ path=%s ; argv[]=%s %s worker %s ; ignore_errors=no ; }' %
                         (d.PYTHON, d.PYTHON, d.CODE, self.rid),
            'User': '', 'Group': '',
        }

    def test_accepts_only_matching_transient_service(self):
        self.assertTrue(d.verify_unit(self.unit, self.rid, self.props))
        for field, value in [('FragmentPath', '/etc/systemd/system/other.service'),
                             ('ControlGroup', '/system.slice/other.service'),
                             ('User', 'other'), ('Type', 'simple'),
                             ('ExecStart', self.props['ExecStart'].replace(self.rid, 'b' * 24))]:
            bad = dict(self.props, **{field: value})
            with self.subTest(field=field), self.assertRaises(d.m.Refused):
                d.verify_unit(self.unit, self.rid, bad)

    def test_stop_refuses_unrelated_unit_without_sending_signal(self):
        bad = dict(self.props, User='other')
        with mock.patch.object(d, 'properties', return_value=bad), \
             mock.patch.object(d.m, 'command') as command:
            with self.assertRaises(d.m.Refused):
                d.stop_unit({'unit': self.unit, 'run_id': self.rid})
            command.assert_not_called()

    def test_unconfirmed_launch_is_not_treated_as_clean(self):
        with mock.patch.object(d, 'properties', return_value={'LoadState': 'not-found'}), \
             mock.patch.object(d.m, 'command') as command:
            with self.assertRaisesRegex(d.m.Refused, 'UNIT_LAUNCH_UNCONFIRMED'):
                d.stop_unit({'unit': self.unit, 'run_id': self.rid, 'phase': 'MOUNTED'})
            command.assert_not_called()

    def test_scan_matches_only_deleted_exact_inode(self):
        files = {'/proc': ['1', '2', 'self'], '/proc/1/fd': ['3', '4'], '/proc/2/fd': ['5']}
        stats = {'/proc/1/fd/3': types.SimpleNamespace(st_dev=9, st_ino=8, st_nlink=0),
                 '/proc/1/fd/4': types.SimpleNamespace(st_dev=9, st_ino=8, st_nlink=1),
                 '/proc/2/fd/5': types.SimpleNamespace(st_dev=9, st_ino=7, st_nlink=0)}
        with mock.patch.object(d.os, 'listdir', side_effect=lambda p: files[p]), \
             mock.patch.object(d.os, 'stat', side_effect=lambda p: stats[p]):
            self.assertEqual(d.open_deleted_refs(9, 8), 1)

    def test_scan_refuses_unreadable_process(self):
        def listing(path):
            if path == '/proc': return ['1']
            raise PermissionError()
        with mock.patch.object(d.os, 'listdir', side_effect=listing):
            with self.assertRaisesRegex(d.m.Refused, 'PROC_FD_INACCESSIBLE'):
                d.open_deleted_refs(9, 8)

    def test_state_must_bind_the_unit_and_inode(self):
        good = {'variant': 'deleted-open', 'run_id': self.rid, 'unit': self.unit,
                'payload_dev': 9, 'payload_ino': 8}
        with mock.patch.object(d.m, 'read_state', return_value=good):
            self.assertIs(d.state_with_unit(10), good)
        for key, value in [('variant', 'inode'), ('unit', 'other'), ('payload_ino', 0)]:
            with self.subTest(key=key), mock.patch.object(d.m, 'read_state', return_value=dict(good, **{key: value})):
                with self.assertRaises(d.m.Refused):
                    d.state_with_unit(10)

    def test_expected_unit_and_run_must_both_match(self):
        state = {'run_id': self.rid, 'unit': self.unit}
        d.require_expected(state, self.rid, self.unit)
        with self.assertRaisesRegex(d.m.Refused, 'RUN_ID_MISMATCH'):
            d.require_expected(state, self.rid, 'other.service')
        with self.assertRaisesRegex(d.m.Refused, 'RUN_ID_MISMATCH'):
            d.require_expected(state, 'b' * 24, self.unit)

    def test_failed_launch_rejects_unknown_named_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            mount = Path(directory)
            payload = mount / 'deleted.log'
            payload.write_bytes(b'not the recorded payload')
            with mock.patch.object(d.m, 'run_path', return_value=mount), \
                 mock.patch.object(d.m, 'verify_mount', return_value=(None, mount, True)):
                with self.assertRaisesRegex(d.m.Refused, 'PAYLOAD_CHANGED'):
                    d.clean_named_payload({'payload_dev': 9, 'payload_ino': 8})
            self.assertTrue(payload.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
