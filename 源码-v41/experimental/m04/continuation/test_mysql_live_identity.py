from dataclasses import replace
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))

import mysql_live_identity as live
from mysql_reset_gate import IdentityRejected, InstanceIdentity, verify_reset_identity

RID = '0123456789abcdef'


class LiveIdentityTests(unittest.TestCase):
    def setUp(self):
        self.state = {'run_id': RID, 'business_phase': 'TEST_ONLY', 'primary_uuid': live.SENTINEL,
                      'boot_id': '11111111-1111-1111-1111-111111111111',
                      'uuids': {'source': '22222222-2222-2222-2222-222222222222',
                                'target': '33333333-3333-3333-3333-333333333333'}}
        self.record = InstanceIdentity(RID, 'source', self.state['boot_id'], self.state['uuids']['source'],
            live.SENTINEL, live.ctl.unit(RID, 'source'), 'abcd' * 8, 4321, 123456, 27,
            '/usr/sbin/mysqld', tuple(live.ctl.command(RID, 'source')),
            '/system.slice/' + live.ctl.unit(RID, 'source'), 21, 2345)

    def test_sentinel_allowed_only_with_explicit_synthetic_mode(self):
        with self.assertRaises(IdentityRejected):
            verify_reset_identity(self.record, self.record, 27, '/usr/sbin/mysqld')
        verify_reset_identity(self.record, self.record, 27, '/usr/sbin/mysqld', synthetic_no_primary=True)
        with self.assertRaises(IdentityRejected):
            verify_reset_identity(self.record, replace(self.record, socket_inode=999), 27,
                                  '/usr/sbin/mysqld', synthetic_no_primary=True)

    def test_replacement_is_rejected_before_database_verification(self):
        verify = unittest.mock.Mock()
        with patch.object(live, 'observe', return_value=replace(self.record, invocation_id='f' * 32)), \
             patch.object(live, 'check', side_effect=lambda a, b: verify_reset_identity(a, b, 27, '/usr/sbin/mysqld', synthetic_no_primary=True)):
            with self.assertRaises(IdentityRejected):
                live.guarded_verify({'source': self.record}, self.state, verify, RID, 'source',
                                    live.SENTINEL, self.state['uuids']['source'])
        verify.assert_not_called()

    def test_replacement_during_database_verification_is_rejected(self):
        verify = unittest.mock.Mock(return_value=self.state['uuids']['source'])
        with patch.object(live, 'observe', side_effect=[self.record, replace(self.record, process_start_ticks=9)]), \
             patch.object(live, 'check', side_effect=lambda a, b: verify_reset_identity(a, b, 27, '/usr/sbin/mysqld', synthetic_no_primary=True)):
            with self.assertRaises(IdentityRejected):
                live.guarded_verify({'source': self.record}, self.state, verify, RID, 'source',
                                    live.SENTINEL, self.state['uuids']['source'])
        verify.assert_called_once()

    def test_reset_stops_on_ambiguous_target_and_preserves_source(self):
        with patch.object(live.ctl, 'properties', return_value={'LoadState': 'not-found', 'ActiveState': 'inactive'}), \
             patch.object(live.ctl, 'verify', side_effect=[None, None, IdentityRejected('changed')]), \
             patch.object(live.ctl, 'stop_one') as stop, patch.object(live.ctl, 'save'):
            with self.assertRaises(IdentityRejected):
                live.reset(RID, self.state, Path('.'))
        stop.assert_not_called()
        self.assertEqual(self.state['phase'], 'STOPPING')

    def test_bind_persists_both_records_before_return(self):
        target = replace(self.record, label='target', server_uuid=self.state['uuids']['target'],
                         unit=live.ctl.unit(RID, 'target'), argv=tuple(live.ctl.command(RID, 'target')),
                         control_group='/system.slice/' + live.ctl.unit(RID, 'target'))
        saved = []
        with patch.object(live, 'observe', side_effect=[self.record, self.record, target, target]), \
             patch.object(live, 'check', side_effect=lambda a, b: verify_reset_identity(a, b, 27, '/usr/sbin/mysqld', synthetic_no_primary=True)), \
             patch.object(live.ctl, 'save', side_effect=lambda d, s: saved.append(dict(s['candidate_identities']))):
            records = live.bind(RID, self.state, Path('.'), unittest.mock.Mock())
        self.assertEqual(set(records), {'source', 'target'})
        self.assertEqual(saved[0]['source']['invocation_id'], self.record.invocation_id)
        self.assertEqual(saved[0]['target']['socket_inode'], target.socket_inode)

    def test_reset_success_records_each_stop_in_order(self):
        stopped, saves = [], []
        with patch.object(live.ctl, 'properties', return_value={'LoadState': 'not-found', 'ActiveState': 'inactive'}), \
             patch.object(live.ctl, 'verify'), \
             patch.object(live.ctl, 'stop_one', side_effect=lambda rid, label: stopped.append(label)), \
             patch.object(live.ctl, 'save', side_effect=lambda d, s: saves.append((s['phase'], list(s.get('candidate_stopped', []))))):
            live.reset(RID, self.state, Path('.'))
        self.assertEqual(stopped, ['target', 'source'])
        self.assertEqual(saves, [('STOPPING', []), ('STOPPING', ['target']),
                                 ('STOPPING', ['target', 'source']), ('STOPPED', ['target', 'source'])])

    def test_reset_requires_no_outstanding_accounts(self):
        self.state['import_account'] = {'name': 'unfinished'}
        with patch.object(live.ctl, 'stop_one') as stop:
            with self.assertRaises(live.ctl.SafetyError):
                live.reset(RID, self.state, Path('.'))
        stop.assert_not_called()


if __name__ == '__main__':
    unittest.main()
