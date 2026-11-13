import contextlib
import io
import json
from pathlib import Path
import stat
import unittest
from unittest.mock import MagicMock, patch

import n04_lifecycle as life


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        if not hasattr(life.socket, 'AF_UNIX'):
            unix = patch.object(life.socket, 'AF_UNIX', 1, create=True)
            unix.start()
            self.addCleanup(unix.stop)
        self.rid = 'a' * 24
        self.invocation = 'b' * 32
        self.unit = life.unit_name(self.rid)
        self.record = {'pid': 123, 'invocation': self.invocation, 'start_ticks': 20,
                       'boot_id': '1' * 8 + '-' + '1' * 4 + '-' + '1' * 4 + '-' + '1' * 4 + '-' + '1' * 12,
                       'sources': {'n04.py': 'c' * 64, 'n04_lifecycle.py': 'd' * 64}}
        self.props = {'Id': self.unit, 'LoadState': 'loaded', 'ActiveState': 'active',
                      'MainPID': '123', 'InvocationID': self.invocation, 'Transient': 'yes',
                      'FragmentPath': '/run/systemd/transient/' + self.unit,
                      'ExecStart': '{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B ' +
                                   str(Path(life.__file__).absolute()) + ' serve ' + self.rid + ' ; }',
                      'ControlGroup': '/system.slice/' + self.unit}

    def test_unit_identity_rejects_foreign_invocation_command_and_group(self):
        self.assertEqual(life.validate_unit(self.rid, self.props), (123, self.invocation))
        for key, value in [('InvocationID', ''), ('ExecStart', 'foreign'), ('ControlGroup', '/other'),
                           ('Transient', 'no'), ('MainPID', '0')]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                life.validate_unit(self.rid, dict(self.props, **{key: value}))

    def test_start_allocates_unique_id_and_bounded_transient_service(self):
        response = {'result': {'event': 'injected', 'fault_proven': False}}
        with patch.object(life, 'protected_sources', return_value=self.record['sources']), \
             patch.object(life, 'base', return_value=Path('/unused')), \
             patch.object(life.os, 'urandom', return_value=bytes.fromhex(self.rid)), \
             patch.object(life.os, 'mkdir') as mkdir, patch.object(life, 'properties_absent', return_value=True), \
             patch.object(life, 'command') as command, patch.object(life.os.path, 'lexists', return_value=True), \
             patch.object(life, 'identity', return_value=self.record), patch.object(life, 'request', return_value=response), \
             patch.object(life, 'save_record') as save, contextlib.redirect_stderr(io.StringIO()):
            receipt = life.start()
        self.assertEqual(receipt['run_id'], self.rid)
        mkdir.assert_called_once_with(Path('/unused') / self.rid, 0o700)
        self.assertIn('--property=RuntimeMaxSec=90s', command.call_args.args)
        self.assertIn('--property=KillMode=control-group', command.call_args.args)
        self.assertIn('--property=TasksMax=4', command.call_args.args)
        save.assert_called_once_with(self.rid, self.record)

    def test_start_refuses_source_changes_before_receipt(self):
        with patch.object(life, 'protected_sources', return_value={'n04.py': 'different'}), \
             patch.object(life, 'base', return_value=Path('/unused')), \
             patch.object(life.os, 'urandom', return_value=bytes.fromhex(self.rid)), \
             patch.object(life.os, 'mkdir'), patch.object(life, 'properties_absent', return_value=True), \
             patch.object(life, 'command'), patch.object(life.os.path, 'lexists', return_value=True), \
             patch.object(life, 'identity', return_value=self.record), \
             patch.object(life, 'save_record') as save, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'sources changed'):
                life.start()
        save.assert_not_called()

    def test_run_id_is_strict_and_duplicate_json_rejected(self):
        for rid in ('../../bad', 'a' * 23, 'A' * 24, 'a' * 24 + '\n'):
            with self.subTest(rid=rid), self.assertRaises(RuntimeError):
                life.unit_name(rid)
        with self.assertRaises(RuntimeError):
            life.unique([('run_id', 1), ('run_id', 2)])

    def test_request_rejects_foreign_peer_before_sending(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        socket_stat = MagicMock(st_mode=stat.S_IFSOCK | 0o600, st_uid=0, st_nlink=1, st_dev=1, st_ino=2)
        with patch.object(life, 'identity', return_value=self.record), \
             patch.object(life, 'run_dir', return_value=Path('/unused')), \
             patch.object(life.os, 'lstat', return_value=socket_stat), \
             patch.object(life.socket, 'socket', return_value=sock), \
             patch.object(life, 'peer', return_value=(999, 0, 0)):
            with self.assertRaisesRegex(RuntimeError, 'peer identity'):
                life.request(self.rid, 'reset', self.record)
        sock.sendall.assert_not_called()

    def test_request_rejects_changed_service_before_connect(self):
        with patch.object(life, 'identity', return_value=dict(self.record, start_ticks=21)), \
             patch.object(life.socket, 'socket') as factory:
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                life.request(self.rid, 'reset', self.record)
        factory.assert_not_called()

    def test_socket_response_must_match_run_and_action(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        socket_stat = MagicMock(st_mode=stat.S_IFSOCK | 0o600, st_uid=0, st_nlink=1, st_dev=1, st_ino=2)
        with patch.object(life, 'identity', return_value=self.record), \
             patch.object(life, 'run_dir', return_value=Path('/unused')), \
             patch.object(life.os, 'lstat', return_value=socket_stat), \
             patch.object(life.socket, 'socket', return_value=sock), \
             patch.object(life, 'peer', return_value=(123, 0, 0)), \
             patch.object(life, 'receive_line', return_value=b'{"run_id":"wrong","action":"check","ok":true}'):
            with self.assertRaisesRegex(RuntimeError, 'invalid response'):
                life.request(self.rid, 'check', self.record)

    def test_reset_response_requires_reset_event_and_socket_identity(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        response = json.dumps({'run_id': self.rid, 'action': 'reset', 'ok': True,
                               'result': {'event': 'reset', 'range_restored': True}}).encode()
        with patch.object(life, 'identity', return_value=self.record), \
             patch.object(life, 'run_dir', return_value=Path('/unused')), \
             patch.object(life, 'control_socket_identity', side_effect=[(1, 2), (1, 3)]), \
             patch.object(life.socket, 'socket', return_value=sock), \
             patch.object(life, 'peer', return_value=(123, 0, 0)), \
             patch.object(life, 'receive_line', return_value=response):
            with self.assertRaisesRegex(RuntimeError, 'socket identity changed'):
                life.request(self.rid, 'reset', self.record)
        wrong = json.dumps({'run_id': self.rid, 'action': 'reset', 'ok': True,
                            'result': {'event': 'check', 'range_restored': True}}).encode()
        with patch.object(life, 'identity', return_value=self.record), \
             patch.object(life, 'run_dir', return_value=Path('/unused')), \
             patch.object(life, 'control_socket_identity', return_value=(1, 2)), \
             patch.object(life.socket, 'socket', return_value=sock), \
             patch.object(life, 'peer', return_value=(123, 0, 0)), \
             patch.object(life, 'receive_line', return_value=wrong):
            with self.assertRaisesRegex(RuntimeError, 'worker event'):
                life.request(self.rid, 'reset', self.record)

    def test_control_socket_rejects_unsafe_objects_without_deletion(self):
        for mode, uid, links in [(stat.S_IFLNK | 0o600, 0, 1), (stat.S_IFSOCK | 0o666, 0, 1),
                                 (stat.S_IFSOCK | 0o600, 1000, 1), (stat.S_IFSOCK | 0o600, 0, 2)]:
            st = MagicMock(st_mode=mode, st_uid=uid, st_nlink=links, st_dev=1, st_ino=2)
            with self.subTest(mode=mode, uid=uid, links=links), \
                 patch.object(life, 'run_dir', return_value=Path('/unused')), \
                 patch.object(life.os, 'lstat', return_value=st), patch.object(life.os, 'unlink') as unlink:
                with self.assertRaisesRegex(RuntimeError, 'unsafe control socket'):
                    life.control_socket_identity(self.rid)
                unlink.assert_not_called()

    def test_serve_handles_check_resolve_reset_in_order(self):
        child = MagicMock()
        child.poll.return_value = None
        child.wait.return_value = 0
        server = MagicMock()
        clients = [MagicMock(), MagicMock(), MagicMock()]
        for client in clients:
            client.__enter__.return_value = client
        server.accept.side_effect = [(client, None) for client in clients]
        messages = [b'check', b'resolve', b'reset']
        outputs = [{'event': 'injected'}, {'event': 'check', 'fault_proven': True},
                   {'event': 'repair', 'range_restored': True, 'reuse_passed': True,
                    'requests_on_one_connection': 8}, {'event': 'reset', 'range_restored': True}]
        with patch.object(life, 'run_dir', return_value=Path('/unused')), \
             patch.object(life, 'protected_sources'), patch.object(life.subprocess, 'Popen', return_value=child), \
             patch.object(life.socket, 'socket', return_value=server), patch.object(life.os.path, 'lexists', return_value=False), \
             patch.object(life.os, 'lstat', return_value=MagicMock(st_mode=stat.S_IFSOCK | 0o600, st_uid=0)), \
             patch.object(life.os, 'umask', return_value=0), \
             patch.object(life, 'peer', return_value=(456, 0, 0)), \
             patch.object(life, 'receive_line', side_effect=messages), patch.object(life, 'worker_line', side_effect=outputs):
            life.serve(self.rid)
        self.assertEqual([call.args[0] for call in child.stdin.write.call_args_list],
                         [b'check\n', b'repair\n', b'reset\n'])
        self.assertTrue(all(json.loads(client.sendall.call_args.args[0])['ok'] for client in clients))
        child.kill.assert_not_called()
        server.close.assert_called_once()

    def test_confirm_stopped_requires_same_invocation_and_empty_cgroup(self):
        stopped = dict(self.props, ActiveState='inactive', MainPID='0', ControlGroup='')
        with patch.object(life, 'properties_absent', return_value=False), patch.object(life, 'properties', return_value=stopped):
            self.assertTrue(life.confirm_stopped(self.rid, self.record))
        with patch.object(life, 'properties_absent', return_value=False), patch.object(life, 'properties', return_value=dict(stopped, InvocationID='f' * 32)):
            with self.assertRaisesRegex(RuntimeError, 'identity unproven'):
                life.confirm_stopped(self.rid, self.record)

    def test_reclaimed_unit_requires_matching_socket_and_absent_pid_twice(self):
        with patch.object(life, 'properties_absent', side_effect=[True, True]) as absent, \
             patch.object(life, 'boot_id', return_value=self.record['boot_id']), \
             patch.object(life, 'process_absent', side_effect=[True, True]) as pid, \
             patch.object(life, 'control_socket_identity', side_effect=[(1, 2), (1, 2)]) as sock:
            self.assertTrue(life.confirm_stopped(self.rid, self.record, (1, 2)))
        self.assertEqual((absent.call_count, pid.call_count, sock.call_count), (2, 2, 2))

    def test_reclaimed_unit_refuses_missing_evidence_pid_or_socket_change(self):
        cases = [(None, True, (1, 2), 'evidence'), ((1, 2), False, (1, 2), 'PID'),
                 ((1, 2), True, (1, 3), 'socket')]
        for sock_id, absent_pid, observed, message in cases:
            with self.subTest(message=message), patch.object(life, 'properties_absent', return_value=True), \
                 patch.object(life, 'boot_id', return_value=self.record['boot_id']), \
                 patch.object(life, 'process_absent', return_value=absent_pid), \
                 patch.object(life, 'control_socket_identity', return_value=observed):
                with self.assertRaisesRegex(RuntimeError, message):
                    life.confirm_stopped(self.rid, self.record, sock_id)

    def test_reclaimed_unit_refuses_unit_or_pid_reappearing(self):
        with patch.object(life, 'properties_absent', side_effect=[True, False]), \
             patch.object(life, 'boot_id', return_value=self.record['boot_id']), \
             patch.object(life, 'process_absent', return_value=True), \
             patch.object(life, 'control_socket_identity', return_value=(1, 2)):
            with self.assertRaisesRegex(RuntimeError, 'unit changed'):
                life.confirm_stopped(self.rid, self.record, (1, 2))

    def test_unit_disappearing_during_inspection_is_rechecked(self):
        with patch.object(life, 'properties_absent', side_effect=[False, True, True]), \
             patch.object(life, 'properties', return_value={'LoadState': 'not-found'}), \
             patch.object(life, 'boot_id', return_value=self.record['boot_id']), \
             patch.object(life, 'process_absent', return_value=True), \
             patch.object(life, 'control_socket_identity', return_value=(1, 2)):
            self.assertTrue(life.confirm_stopped(self.rid, self.record, (1, 2)))

    def test_incomplete_systemd_properties_only_allow_confirmed_not_found(self):
        with patch.object(life, 'command', return_value='LoadState=not-found\n'), \
             patch.object(life, 'properties_absent', return_value=True):
            self.assertEqual(life.properties(self.rid), {'LoadState': 'not-found'})
        with patch.object(life, 'command', return_value='LoadState=not-found\n'), \
             patch.object(life, 'properties_absent', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                life.properties(self.rid)
        with patch.object(life, 'command', return_value='LoadState=loaded\n'), \
             patch.object(life, 'properties_absent') as absent:
            with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                life.properties(self.rid)
        absent.assert_not_called()

    def test_process_absence_rejects_access_errors_and_reused_pid(self):
        with patch.object(life.os, 'stat', side_effect=[MagicMock(), FileNotFoundError]):
            self.assertTrue(life.process_absent(123))
        with patch.object(life.os, 'stat', side_effect=[MagicMock(), MagicMock()]):
            self.assertFalse(life.process_absent(123))
        with patch.object(life.os, 'stat', side_effect=[MagicMock(), PermissionError]):
            with self.assertRaises(PermissionError):
                life.process_absent(123)
        with patch.object(life, 'properties_absent', return_value=True), \
             patch.object(life, 'boot_id', return_value=self.record['boot_id']), \
             patch.object(life, 'process_absent', side_effect=[True, False]), \
             patch.object(life, 'control_socket_identity', return_value=(1, 2)):
            with self.assertRaisesRegex(RuntimeError, 'PID reappeared'):
                life.confirm_stopped(self.rid, self.record, (1, 2))

    def test_check_exit_codes_distinguish_fault_recovery_and_inconclusive(self):
        for result, code in [({'fault_proven': True, 'repaired': False}, 1),
                             ({'fault_proven': False, 'repaired': True}, 0),
                             ({'fault_proven': False, 'repaired': False}, 2)]:
            response = {'ok': True, 'result': result}
            with self.subTest(result=result), patch.object(life.sys, 'platform', 'linux'), \
                 patch.object(life, 'guard'), patch.object(life, 'protected_sources'), \
                 patch.object(life, 'read_record', return_value=self.record), \
                 patch.object(life, 'request', return_value=response), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(life.main(['check', self.rid]), code)

    def test_reset_cannot_succeed_without_confirmed_exit(self):
        response = {'ok': True, 'result': {'event': 'reset', 'range_restored': True}, '_socket_identity': (1, 2)}
        with patch.object(life.sys, 'platform', 'linux'), patch.object(life, 'guard'), \
             patch.object(life, 'protected_sources'), patch.object(life, 'repeat_reset', return_value=False), \
             patch.object(life, 'read_record', return_value=self.record), \
             patch.object(life, 'request', return_value=response), \
             patch.object(life, 'confirm_stopped', side_effect=RuntimeError('not confirmed')), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaisesRegex(RuntimeError, 'not confirmed'):
                life.main(['reset', self.rid])
        self.assertEqual(out.getvalue(), '')

    def test_unknown_run_id_cannot_report_clean(self):
        with patch.object(life.sys, 'platform', 'linux'), patch.object(life, 'guard'), \
             patch.object(life, 'protected_sources'), patch.object(life, 'read_record', side_effect=FileNotFoundError), \
             patch.object(life, 'request') as request, contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(FileNotFoundError):
                life.main(['reset', self.rid])
        request.assert_not_called()
        self.assertEqual(out.getvalue(), '')

    def test_repeated_reset_requires_verified_completion_and_does_not_contact_worker(self):
        with patch.object(life.sys, 'platform', 'linux'), patch.object(life, 'guard'), \
             patch.object(life, 'protected_sources'), patch.object(life, 'read_record', return_value=self.record), \
             patch.object(life, 'repeat_reset', return_value=True), patch.object(life, 'request') as request, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(life.main(['reset', self.rid]), 0)
        request.assert_not_called()
        self.assertTrue(json.loads(out.getvalue())['already_completed'])

    def test_repeat_reset_requires_bound_receipt_same_boot_and_absent_unit(self):
        with patch.object(life, 'completion', return_value=(1, 2)), \
             patch.object(life, 'boot_id', return_value=self.record['boot_id']), \
             patch.object(life, 'protected_sources', return_value=self.record['sources']), \
             patch.object(life, 'properties_absent', side_effect=[True, True]) as absent, \
             patch.object(life, 'process_absent', return_value=True), \
             patch.object(life, 'control_socket_identity', return_value=(1, 2)):
            self.assertTrue(life.repeat_reset(self.rid, self.record))
        self.assertEqual(absent.call_count, 2)
        with patch.object(life, 'completion', return_value=(1, 2)), \
             patch.object(life, 'boot_id', return_value='other'):
            with self.assertRaisesRegex(RuntimeError, 'environment changed'):
                life.repeat_reset(self.rid, self.record)
        with patch.object(life, 'completion', return_value=(1, 2)), \
             patch.object(life, 'boot_id', return_value=self.record['boot_id']), \
             patch.object(life, 'protected_sources', return_value=self.record['sources']), \
             patch.object(life, 'process_absent', return_value=True), \
             patch.object(life, 'control_socket_identity', return_value=(1, 3)), \
             patch.object(life, 'confirm_stopped') as confirm:
            with self.assertRaisesRegex(RuntimeError, 'socket identity changed'):
                life.repeat_reset(self.rid, self.record)
            confirm.assert_not_called()

    def test_completion_read_rejects_other_run_or_tampering(self):
        record = life.completion_data(self.rid, self.record, (1, 2))
        marker = MagicMock(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1, st_size=0)
        legacy = {key: value for key, value in record.items() if key != 'socket_identity'}
        for changed in [dict(record, run_id='e' * 24), dict(record, result='clean'), legacy]:
            data = json.dumps(changed).encode()
            marker.st_size = len(data)
            with self.subTest(changed=changed), \
                 patch.object(life, 'run_dir', return_value=Path('/unused')), \
                 patch.object(life.os, 'O_NOFOLLOW', 0, create=True), \
                 patch.object(life.os, 'O_NONBLOCK', 0, create=True), \
                 patch.object(life.os, 'O_CLOEXEC', 0, create=True), \
                 patch.object(life.os, 'open', return_value=42), patch.object(life.os, 'close'), \
                 patch.object(life.os, 'fstat', return_value=marker), patch.object(life.os, 'read', return_value=data):
                with self.assertRaisesRegex(RuntimeError, 'completion identity mismatch'):
                    life.completion(self.rid, self.record)
        with patch.object(life, 'completion', return_value=(1, 2)), \
             patch.object(life, 'boot_id', return_value=self.record['boot_id']), \
             patch.object(life, 'protected_sources', return_value=self.record['sources']), \
             patch.object(life, 'properties_absent', side_effect=[True, False]), \
             patch.object(life, 'process_absent', return_value=True), \
             patch.object(life, 'control_socket_identity', return_value=(1, 2)):
            with self.assertRaisesRegex(RuntimeError, 'unit changed'):
                life.repeat_reset(self.rid, self.record)

    def test_successful_reset_writes_receipt_only_after_exit_confirmed(self):
        response = {'ok': True, 'result': {'event': 'reset', 'range_restored': True}, '_socket_identity': (1, 2)}
        order = []
        with patch.object(life.sys, 'platform', 'linux'), patch.object(life, 'guard'), \
             patch.object(life, 'protected_sources'), patch.object(life, 'read_record', return_value=self.record), \
             patch.object(life, 'repeat_reset', return_value=False), patch.object(life, 'request', return_value=response), \
             patch.object(life, 'confirm_stopped', side_effect=lambda *a: order.append('stopped')), \
             patch.object(life, 'completion', side_effect=lambda *a, **kw: order.append('receipt')), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(life.main(['reset', self.rid]), 0)
        self.assertEqual(order, ['stopped', 'receipt'])


if __name__ == '__main__':
    unittest.main()
