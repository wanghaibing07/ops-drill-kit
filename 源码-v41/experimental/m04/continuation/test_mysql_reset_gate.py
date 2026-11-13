from dataclasses import replace
from pathlib import Path
import sys
import types
import unittest

PARENT = str(Path(__file__).resolve().parent.parent)
if PARENT not in sys.path:
    sys.path.insert(0, PARENT)
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))

import m04_controller as ctl
from mysql_reset_gate import IdentityRejected, InstanceIdentity, verify_reset_identity


class ResetIdentityTests(unittest.TestCase):
    def setUp(self):
        rid = '0123456789abcdef'
        self.record = InstanceIdentity(
            rid, 'target', '11111111-1111-1111-1111-111111111111',
            '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333',
            ctl.unit(rid, 'target'), 'abcd' * 8, 4321, 123456, 27, '/usr/sbin/mysqld',
            tuple(ctl.command(rid, 'target')), '/system.slice/' + ctl.unit(rid, 'target'), 21, 2345)

    def check(self, record, observed):
        verify_reset_identity(record, observed, 27, '/usr/sbin/mysqld')

    def test_matching_record_and_live_observation(self):
        self.check(self.record, self.record)

    def test_refuses_every_live_identity_change(self):
        changes = {'run_id': 'fedcba9876543210', 'label': 'source',
                   'boot_id': '44444444-4444-4444-4444-444444444444',
                   'server_uuid': '55555555-5555-5555-5555-555555555555',
                   'primary_uuid': '66666666-6666-6666-6666-666666666666',
                   'unit': 'other.service', 'invocation_id': 'dcba' * 8, 'pid': 4322,
                   'process_start_ticks': 123457, 'uid': 28, 'executable': '/tmp/mysqld',
                   'argv': ('mysqld',), 'control_group': '/other', 'socket_device': 22,
                   'socket_inode': 2346}
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaises(IdentityRejected):
                self.check(self.record, replace(self.record, **{field: value}))

    def test_rejects_bad_or_forged_record_even_if_live_matches(self):
        variants = [replace(self.record, run_id='../x'), replace(self.record, unit='other.service'),
                    replace(self.record, server_uuid=self.record.primary_uuid),
                    replace(self.record, invocation_id='0' * 32), replace(self.record, pid=1),
                    replace(self.record, process_start_ticks=0), replace(self.record, socket_inode=0),
                    replace(self.record, uid=0), replace(self.record, argv=('mysqld',)),
                    replace(self.record, boot_id='not-a-uuid')]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(IdentityRejected):
                self.check(value, value)
        with self.assertRaises(IdentityRejected):
            self.check(self.record, None)


if __name__ == '__main__':
    unittest.main()
