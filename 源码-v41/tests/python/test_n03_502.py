import contextlib
import importlib.util
import io
import json
import pathlib
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

source = pathlib.Path(__file__).with_name('n03_502.py')
if not source.exists():
    source = pathlib.Path(__file__).resolve().parents[2] / 'experimental/n03-c01/n03_502.py'
spec = importlib.util.spec_from_file_location('n03_502_test', source)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class WatchdogSafetyTests(unittest.TestCase):
    def setUp(self):
        self.rid = 'a' * 24
        self.sha = 'b' * 64
        self.state = {'run_id': self.rid, 'timer': 'opsdrill-n03-recover-' + self.rid + '.timer',
                      'helper_sha': self.sha, 'helper': 'helper-' + self.sha + '.py', 'service_sha': 'c' * 64}
        self.unit = self.state['timer'][:-6] + '.service'
        self.timer = {'LoadState': 'loaded', 'ActiveState': 'active',
                      'FragmentPath': '/run/systemd/transient/' + self.state['timer'], 'Unit': self.unit,
                      'TimersMonotonic': '{ OnActiveUSec=2min ; next_elapse=1h }', 'NextElapseUSecMonotonic': '1h'}
        self.watchdog = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'Type': 'exec', 'User': '',
                         'FragmentPath': '/run/systemd/transient/' + self.unit,
                         'ExecStart': '{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 %s watchdog %s ; ignore_errors=no ; }'
                                      % (m.helper_path(self.state), self.rid)}

    def test_502_resolve_restores_only_the_matching_run(self):
        state = dict(self.state, kind='n03-502', phase='FAULT')
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), mock.patch.object(m, 'helper_verified') as helper, \
             mock.patch.object(m, 'restore_service', return_value='STARTED') as restore, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.resolve(self.rid), 0)
            self.assertEqual(json.loads(output.getvalue()), {'status': 'MITIGATED', 'service_action': 'STARTED'})
            helper.assert_called_once_with(state)
            restore.assert_called_once_with(state)

    def test_resolve_refuses_different_run_before_restoring_service(self):
        state = dict(self.state, kind='n03-502', phase='FAULT')
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), mock.patch.object(m, 'helper_verified') as helper, \
             mock.patch.object(m, 'restore_service') as restore:
            with self.assertRaisesRegex(m.Refused, 'RUN_ID_MISMATCH'):
                m.resolve('d' * 24)
            helper.assert_not_called()
            restore.assert_not_called()

    def test_504_resolve_only_removes_its_gate(self):
        state = dict(self.state, kind='n03-504', phase='FAULT')
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), mock.patch.object(m, 'helper_verified'), \
             mock.patch.object(m, 'remove_gate', return_value=True) as remove, \
             mock.patch.object(m, 'service_identity', return_value=({'ActiveState': 'active'}, state['service_sha'])), \
             mock.patch.object(m, 'wait_ready'), mock.patch.object(m, 'request', return_value=(404, None)), \
             mock.patch.object(m, 'restore_service') as restore, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.resolve(self.rid), 0)
            self.assertEqual(json.loads(output.getvalue()), {'status': 'MITIGATED', 'gate_removed': True})
            remove.assert_called_once_with(state)
            restore.assert_not_called()

    def test_exact_timer_and_helper_identity_required(self):
        self.assertTrue(m.verify_timer(self.state, self.timer))
        self.assertTrue(m.verify_watchdog_service(self.state, self.watchdog))
        for key, value in [('FragmentPath', '/etc/systemd/system/foreign.service'),
                           ('User', 'other'), ('ExecStart', self.watchdog['ExecStart'].replace(self.rid, 'd' * 24))]:
            with self.subTest(key=key), self.assertRaises(m.Refused):
                m.verify_watchdog_service(self.state, dict(self.watchdog, **{key: value}))
        with self.assertRaises(m.Refused):
            m.verify_timer(self.state, dict(self.timer, Unit='foreign.service'))

    def test_cannot_stop_service_without_verified_armed_timer(self):
        p = {'ActiveState': 'active', 'SubState': 'running', 'MainPID': '123', 'InvocationID': 'e' * 32}
        written = []
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=None), mock.patch.object(m, 'require_no_orphans'), \
             mock.patch.object(m, 'service_identity', return_value=(p, 'c' * 64)), mock.patch.object(m, 'ready', return_value=True), \
             mock.patch.object(m, 'install_helper', return_value=(self.state['helper'], self.sha)), \
             mock.patch.object(m, 'write_state', side_effect=lambda _fd, state: written.append(dict(state))), \
             mock.patch.object(m, 'arm_watchdog', side_effect=m.Refused('WATCHDOG_NOT_ARMED')), \
             mock.patch.object(m, 'run') as run:
            with self.assertRaisesRegex(m.Refused, 'WATCHDOG_NOT_ARMED'):
                m.inject()
            run.assert_not_called()
            self.assertEqual([state['phase'] for state in written], ['PREPARING'])

    def test_arm_rejects_unarmed_or_mismatched_timer(self):
        with mock.patch.object(m, 'helper_verified'), mock.patch.object(m, 'run'), \
             mock.patch.object(m, 'timer_properties', return_value=self.timer), \
             mock.patch.object(m, 'watchdog_service_properties', return_value=self.watchdog):
            m.arm_watchdog(self.state)
        with mock.patch.object(m, 'helper_verified'), mock.patch.object(m, 'run'), \
             mock.patch.object(m, 'timer_properties', return_value=dict(self.timer, ActiveState='inactive')), \
             mock.patch.object(m, 'watchdog_service_properties', return_value=self.watchdog):
            with self.assertRaisesRegex(m.Refused, 'WATCHDOG_NOT_ARMED'):
                m.arm_watchdog(self.state)

    def test_lost_timer_after_preparation_never_stops_service(self):
        p = {'ActiveState': 'active', 'SubState': 'running', 'MainPID': '123', 'InvocationID': 'e' * 32}
        written = []
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=None), mock.patch.object(m, 'require_no_orphans'), \
             mock.patch.object(m, 'service_identity', return_value=(p, 'c' * 64)), mock.patch.object(m, 'ready', return_value=True), \
             mock.patch.object(m, 'install_helper', return_value=(self.state['helper'], self.sha)), \
             mock.patch.object(m, 'write_state', side_effect=lambda _fd, state: written.append(dict(state))), \
             mock.patch.object(m, 'arm_watchdog'), \
             mock.patch.object(m, 'require_watchdog_armed', side_effect=m.Refused('WATCHDOG_NOT_ARMED')), \
             mock.patch.object(m, 'run') as run:
            with self.assertRaisesRegex(m.Refused, 'WATCHDOG_NOT_ARMED'):
                m.inject()
            run.assert_not_called()
            self.assertEqual([state['phase'] for state in written], ['PREPARING', 'STOP_REQUESTED'])

    def test_service_config_drift_never_triggers_start(self):
        p = {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0'}
        with mock.patch.object(m, 'service_identity', return_value=(p, 'd' * 64)), mock.patch.object(m, 'run') as run:
            with self.assertRaisesRegex(m.Refused, 'SERVICE_CONFIG_CHANGED'):
                m.restore_service(self.state)
            run.assert_not_called()

    def test_watchdog_preparing_state_never_restarts_service(self):
        state = dict(self.state, phase='PREPARING')
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), mock.patch.object(m, 'helper_verified'), \
             mock.patch.object(m, 'CODE', m.helper_path(state)), \
             mock.patch.object(m, 'service_identity', return_value=({'ActiveState': 'active'}, state['service_sha'])), \
             mock.patch.object(m, 'ready', return_value=True), mock.patch.object(m, 'write_state') as write, \
             mock.patch.object(m, 'restore_service') as restore:
            self.assertEqual(m.watchdog(self.rid), 0)
            restore.assert_not_called()
            self.assertEqual(write.call_args.args[1]['watchdog_action'], 'PREPARE_OBSERVED_ACTIVE')

    def test_restart_only_exact_known_inactive_service(self):
        p = {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0'}
        with mock.patch.object(m, 'service_identity', return_value=(p, self.state['service_sha'])), \
             mock.patch.object(m, 'wait_ready'), mock.patch.object(m, 'run') as run:
            self.assertEqual(m.restore_service(self.state), 'STARTED')
            run.assert_called_once_with('/usr/bin/systemctl', 'start', m.SERVICE, timeout=20)
        with mock.patch.object(m, 'service_identity', return_value=(dict(p, ActiveState='failed'), self.state['service_sha'])), \
             mock.patch.object(m, 'run') as run:
            with self.assertRaisesRegex(m.Refused, 'SERVICE_STATE_AMBIGUOUS'):
                m.restore_service(self.state)
            run.assert_not_called()

    def test_wrong_run_id_refuses_before_service_changes(self):
        state = dict(self.state, phase='FAULT')
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), mock.patch.object(m, 'restore_service') as restore:
            with self.assertRaisesRegex(m.Refused, 'RUN_ID_MISMATCH'):
                m.reset('f' * 24)
            restore.assert_not_called()

    def test_owner_verification_requires_same_armed_timer(self):
        state = dict(self.state, phase='FAULT', kind='n03-502')
        service = {'ActiveState':'inactive', 'SubState':'dead', 'MainPID':'0'}
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), mock.patch.object(m, 'helper_verified'), \
             mock.patch.object(m, 'require_watchdog_armed') as armed, \
             mock.patch.object(m, 'service_identity', return_value=(service, state['service_sha'])), \
             mock.patch.object(m, 'request', return_value=(502, None)):
            self.assertEqual(m.verify_owner(self.rid, self.state['timer']), 0)
            armed.assert_called_once_with(state)
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), mock.patch.object(m, 'require_watchdog_armed') as armed:
            with self.assertRaisesRegex(m.Refused, 'BAD_OWNER'):
                m.verify_owner(self.rid, 'foreign.timer')
            armed.assert_not_called()

    def test_orphan_watchdog_refuses_new_attempt(self):
        with mock.patch.object(m, 'run', return_value='opsdrill-n03-recover-other.timer loaded active waiting'):
            with self.assertRaisesRegex(m.Refused, 'ORPHAN_WATCHDOG'):
                m.require_no_orphans()

    def test_504_watchdog_removes_only_gate_without_restarting_service(self):
        state = dict(self.state, phase='FAULT', kind='n03-504')
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), mock.patch.object(m, 'helper_verified'), \
             mock.patch.object(m, 'CODE', m.helper_path(state)), mock.patch.object(m, 'remove_gate', return_value=True) as remove, \
             mock.patch.object(m, 'service_identity', return_value=({'ActiveState':'active'}, state['service_sha'])), \
             mock.patch.object(m, 'wait_ready'), mock.patch.object(m, 'request', return_value=(404, None)), \
             mock.patch.object(m, 'write_state') as write, mock.patch.object(m, 'restore_service') as restore:
            self.assertEqual(m.watchdog(self.rid), 0)
            remove.assert_called_once_with(state)
            restore.assert_not_called()
            self.assertEqual(write.call_args.args[1]['watchdog_action'], 'GATE_REMOVED')

    def test_504_cannot_create_gate_if_watchdog_is_not_armed(self):
        p = {'ActiveState': 'active', 'SubState': 'running', 'MainPID': '123', 'InvocationID': 'e' * 32}
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=None), mock.patch.object(m, 'require_no_orphans'), \
             mock.patch.object(m, 'service_identity', return_value=(p, 'c' * 64)), mock.patch.object(m, 'ready', return_value=True), \
             mock.patch.object(m, 'request', return_value=(404, None)), \
             mock.patch.object(m, 'install_helper', return_value=(self.state['helper'], self.sha)), \
             mock.patch.object(m, 'write_state'), mock.patch.object(m, 'arm_watchdog', side_effect=m.Refused('WATCHDOG_NOT_ARMED')), \
             mock.patch.object(m, 'create_gate') as create:
            with self.assertRaisesRegex(m.Refused, 'WATCHDOG_NOT_ARMED'):
                m.inject(variant='504')
            create.assert_not_called()

    def test_old_watchdog_cannot_remove_a_new_runs_gate(self):
        new_state = dict(self.state, run_id='f' * 24, phase='FAULT', kind='n03-504')
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=new_state), mock.patch.object(m, 'remove_gate') as remove:
            with self.assertRaisesRegex(m.Refused, 'RUN_ID_MISMATCH'):
                m.watchdog(self.rid)
            remove.assert_not_called()

    def test_504_active_check_reports_gate_without_claiming_a_fresh_http_probe(self):
        state = dict(self.state, phase='FAULT', kind='n03-504')
        output = io.StringIO()
        with mock.patch.object(m, 'guard'), mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(7)), \
             mock.patch.object(m, 'read_state', return_value=state), \
             mock.patch.object(m, 'service_identity', return_value=({'ActiveState': 'active'}, state['service_sha'])), \
             mock.patch.object(m, 'ready', return_value=True), mock.patch.object(m, 'gate_present', return_value=True), \
             mock.patch.object(m, 'gate_live', return_value=True), mock.patch.object(m, 'request') as request, \
             contextlib.redirect_stdout(output):
            self.assertEqual(m.check(self.rid), 1)
        self.assertEqual(json.loads(output.getvalue()), {'status': 'FAULT_PRESENT', 'gate': 'active'})
        request.assert_not_called()


@unittest.skipUnless(os.geteuid() == 0, 'gate ownership checks require root')
class GateSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name) / 'gate'
        patch = mock.patch.object(m, 'GATE_DIR', self.path)
        patch.start()
        self.addCleanup(patch.stop)
        self.rid = 'a' * 24
        now = time.monotonic_ns()
        self.state = {'run_id': self.rid, 'boot_id': m.BOOT_ID.read_text(encoding='ascii').strip(),
                      'gate_created_ns': now, 'gate_expires_ns': now + 60_000_000_000}

    def test_create_remove_and_wrong_run_preserves_gate(self):
        m.create_gate(self.state)
        self.assertTrue(m.gate_present(self.state))
        with self.assertRaisesRegex(m.Refused, 'GATE_OWNER_MISMATCH'):
            m.remove_gate(dict(self.state, run_id='b' * 24))
        self.assertTrue(m.gate_present(self.state))
        self.assertTrue(m.remove_gate(self.state))
        self.assertFalse(m.remove_gate(self.state))

    def test_interrupted_link_and_partial_temp_are_recoverable(self):
        self.path.mkdir(mode=0o755)
        self.path.chmod(0o755)  # Independent of the invoking process umask.
        temp = self.path / ('.new-' + self.rid)
        temp.write_bytes(m.gate_payload(self.state))
        temp.chmod(0o644)
        os.link(temp, self.path / m.GATE_NAME)
        self.assertTrue(m.remove_gate(self.state))
        temp.write_bytes(m.gate_payload(self.state)[:7])
        temp.chmod(0o644)
        self.assertTrue(m.remove_gate(self.state))
        self.assertEqual(list(self.path.iterdir()), [])

    def test_foreign_file_and_symlink_are_never_removed(self):
        self.path.mkdir(mode=0o755)
        self.path.chmod(0o755)  # Independent of the invoking process umask.
        foreign = self.path / 'unrelated'
        foreign.write_bytes(b'preserve')
        with self.assertRaisesRegex(m.Refused, 'UNOWNED_GATE'):
            m.remove_gate(self.state)
        self.assertEqual(foreign.read_bytes(), b'preserve')
        foreign.unlink()
        link = self.path / m.GATE_NAME
        link.symlink_to('/etc/passwd')
        with self.assertRaises(OSError):
            m.remove_gate(self.state)
        self.assertTrue(link.is_symlink())

    def test_old_waiting_watchdog_cannot_remove_new_runs_gate(self):
        root = pathlib.Path(self.tmp.name) / 'state'
        now = time.monotonic_ns()
        boot = m.BOOT_ID.read_text(encoding='ascii').strip()
        def state(rid):
            sha = 'b' * 64
            return {'version': 1, 'kind': 'n03-504', 'run_id': rid, 'phase': 'FAULT',
                    'timer': 'opsdrill-n03-recover-' + rid + '.timer', 'helper_sha': sha,
                    'helper': 'helper-' + sha + '.py', 'service_sha': 'c' * 64, 'boot_id': boot,
                    'original_pid': 123, 'original_invocation': 'd' * 32,
                    'gate_created_ns': now, 'gate_expires_ns': now + 60_000_000_000}
        old, new = state('a' * 24), state('b' * 24)
        entered = threading.Event()
        outcome = []
        def delayed_watchdog():
            entered.set()
            try:
                m.watchdog(old['run_id'])
            except m.Refused as exc:
                outcome.append(str(exc))
            except Exception as exc:
                outcome.append(type(exc).__name__)
        with mock.patch.object(m, 'ROOT', root), mock.patch.object(m, 'guard'):
            with m.locked() as dfd:
                m.write_state(dfd, old)
                m.create_gate(old)
                lock_inode = (root / m.LOCK).stat().st_ino
                thread = threading.Thread(target=delayed_watchdog, daemon=True)
                thread.start()
                self.assertTrue(entered.wait(2))
                m.remove_gate(old)
                m.write_state(dfd, new)
                m.create_gate(new)
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(outcome, ['RUN_ID_MISMATCH'])
            self.assertEqual((root / m.LOCK).stat().st_ino, lock_inode)
            self.assertTrue(m.gate_present(new))
            self.assertTrue(m.remove_gate(new))


if __name__ == '__main__':
    unittest.main(verbosity=2)
