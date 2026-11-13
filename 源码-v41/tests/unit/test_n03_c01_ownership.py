import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import threading
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

# The Windows host lacks fcntl. All controller locks in these tests are replaced
# by controlled mocks; this does not test Linux flock or filesystem security.
if 'fcntl' not in sys.modules:
    try:
        import fcntl
    except ImportError:
        sys.modules['fcntl'] = types.SimpleNamespace()
path = pathlib.Path(__file__).resolve().parents[2] / 'experimental/n03-c01/n03_502.py'
spec = importlib.util.spec_from_file_location('n03_candidate', path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.rid, self.owner = 'a'*24, 'b'*32
        self.binding = (self.rid, self.owner)
        self.state = {'kind': 'n03-502', 'run_id': self.rid, 'phase': 'FAULT',
                      'timer': 'opsdrill-n03-recover-'+self.rid+'.timer',
                      'owner_kind': 'C01_APP_DOWN_V1', 'owner_id': self.owner,
                      'service_sha': 'c'*64}
        self.guard = mock.patch.object(m, 'guard'); self.guard.start(); self.addCleanup(self.guard.stop)
        self.lock = mock.patch.object(m, 'locked', return_value=contextlib.nullcontext(42)); self.lock.start(); self.addCleanup(self.lock.stop)
        self.read = mock.patch.object(m, 'read_state', return_value=self.state); self.read.start(); self.addCleanup(self.read.stop)

    def test_ordinary_direct_entrypoints_refuse_even_with_run_id(self):
        actions = [lambda: m.check(), lambda: m.check(self.rid), lambda: m.resolve(self.rid),
                   lambda: m.reset(), lambda: m.reset(self.rid),
                   lambda: m.verify_owner(self.rid, self.state['timer'])]
        with mock.patch.object(m, 'helper_verified') as helper, mock.patch.object(m, 'service_identity') as svc, \
             mock.patch.object(m, 'restore_service') as restore, mock.patch.object(m, 'cancel_watchdog') as cancel:
            for action in actions:
                with self.subTest(action=action), self.assertRaisesRegex(m.Refused, 'C01_OWNS_N03'):
                    action()
            helper.assert_not_called(); svc.assert_not_called(); restore.assert_not_called(); cancel.assert_not_called()

    def test_wrong_or_stale_binding_fails_before_mutation(self):
        with mock.patch.object(m, 'helper_verified') as helper, mock.patch.object(m, 'restore_service') as restore:
            for binding in [(self.rid, 'f'*32), ('d'*24, self.owner)]:
                for action in [lambda: m.check(binding[0], binding), lambda: m.resolve(binding[0], binding),
                               lambda: m.reset(binding[0], binding)]:
                    with self.assertRaises(m.Refused): action()
            helper.assert_not_called(); restore.assert_not_called()

    def test_owned_resolve_and_user_manually_started_service_are_supported(self):
        with mock.patch.object(m, 'helper_verified'), \
             mock.patch.object(m, 'restore_service', return_value='ALREADY_ACTIVE') as restore, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.resolve(self.rid, self.binding), 0)
            restore.assert_called_once_with(self.state)

    def test_owned_reset_cannot_be_claimed_idempotent_after_state_disappears(self):
        with mock.patch.object(m, 'read_state', return_value=None), \
             mock.patch.object(m, 'require_no_orphans') as clean:
            with self.assertRaisesRegex(m.Refused, 'RUN_ID_MISMATCH'):
                m.reset(self.rid, self.binding)
            clean.assert_not_called()

    def test_unowned_legacy_manual_check_and_resolve_remain_allowed(self):
        self.state.pop('owner_kind'); self.state.pop('owner_id')
        with mock.patch.object(m, 'service_identity', return_value=({'ActiveState':'active'},'c'*64)), \
             mock.patch.object(m, 'ready', return_value=True), mock.patch.object(m, 'helper_verified'), \
             mock.patch.object(m, 'restore_service', return_value='ALREADY_ACTIVE'), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.check(), 0)
            self.assertEqual(m.resolve(self.rid), 0)

    def test_owned_attempt_never_adopts_existing_manual_n03(self):
        self.state.pop('owner_kind'); self.state.pop('owner_id')
        with mock.patch.object(m, 'require_no_orphans') as clean, mock.patch.object(m, 'write_state') as write:
            with self.assertRaisesRegex(m.Refused, 'PREVIOUS_RUN_REQUIRES_RESET'):
                m.inject(binding=self.binding)
            clean.assert_not_called(); write.assert_not_called()

    def test_binding_persisted_before_watchdog_and_injection(self):
        captured = []
        p = {'ActiveState':'active', 'SubState':'running', 'MainPID':'42', 'InvocationID':'d'*32}
        with mock.patch.object(m, 'read_state', return_value=None), mock.patch.object(m, 'require_no_orphans'), \
             mock.patch.object(m, 'service_identity', return_value=(p, 'c'*64)), mock.patch.object(m, 'ready', return_value=True), \
             mock.patch.object(m, 'install_helper', return_value=('helper-'+'e'*64+'.py', 'e'*64)), \
             mock.patch.object(m, 'write_state', side_effect=lambda fd, state: captured.append(dict(state))), \
             mock.patch.object(m, 'arm_watchdog', side_effect=m.Refused('INTERRUPTED')), \
             mock.patch.object(m, 'run') as run, \
             mock.patch.object(m, 'BOOT_ID', types.SimpleNamespace(read_text=lambda **kwargs:'boot')):
            with self.assertRaisesRegex(m.Refused, 'INTERRUPTED'):
                m.inject(binding=self.binding)
            self.assertEqual(len(captured), 1)
            self.assertEqual((captured[0]['phase'], captured[0]['run_id'], captured[0]['owner_id']),
                             ('PREPARING', self.rid, self.owner))
            run.assert_not_called()

    def test_watchdog_still_processes_owned_matching_state(self):
        self.state['phase'] = 'WATCHDOG_HEALTHY'
        with mock.patch.object(m, 'helper_verified'), mock.patch.object(m, 'helper_path', return_value=m.CODE), \
             mock.patch.object(m, 'restore_service', return_value='ALREADY_ACTIVE') as restore, \
             mock.patch.object(m, 'write_state') as write, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.watchdog(self.rid, self.owner), 0)
            restore.assert_called_once(); write.assert_called_once()
            self.assertEqual(self.state['phase'], 'WATCHDOG_HEALTHY')

    def test_old_watchdog_cannot_touch_new_owned_run(self):
        with mock.patch.object(m, 'restore_service') as restore:
            with self.assertRaisesRegex(m.Refused, 'RUN_ID_MISMATCH'):
                m.watchdog('e'*24)
            restore.assert_not_called()

    def test_main_validates_owned_arguments(self):
        for args in [['program', 'c01-inject', 'bad', self.owner],
                     ['program', 'c01-reset', self.rid], ['program', 'c01-check', self.rid, self.owner, 'extra']]:
            with self.assertRaises(m.Refused): m.main(args)

    def test_no_owned_access_to_legacy_or_other_variant(self):
        with self.assertRaisesRegex(m.Refused, 'C01_OWNER_MISMATCH'):
            m.authorize_state({'kind':'n03-502','run_id':self.rid, 'timer':self.state['timer']}, self.binding)
        state = dict(self.state, kind='n03-504')
        with self.assertRaisesRegex(m.Refused, 'C01_OWNER_MISMATCH'): m.authorize_state(state, self.binding)


    def test_state_decoder_rejects_partial_unknown_and_wrong_variant_owners(self):
        self.read.stop()  # Exercise the real parser rather than the fixture mock.
        boot = '12345678-1234-1234-1234-123456789abc'
        sha = 'e'*64
        base = dict(version=1, kind='n03-502', run_id=self.rid, phase='FAULT',
                    timer=self.state['timer'], helper_sha=sha, helper='helper-'+sha+'.py',
                    service_sha='c'*64, boot_id=boot, original_pid=42, original_invocation='d'*32)
        meta = types.SimpleNamespace(st_mode=0o100600, st_uid=0, st_nlink=1, st_size=500)
        bad = [dict(owner_kind='C01_APP_DOWN_V1'), dict(owner_id=self.owner),
               dict(owner_kind=None, owner_id=None), dict(owner_kind='OTHER', owner_id=self.owner),
               dict(owner_kind='C01_APP_DOWN_V1', owner_id='bad'),
               dict(owner_kind='C01_APP_DOWN_V1', owner_id=self.owner, kind='n03-504')]
        with mock.patch.object(m.os, 'O_NOFOLLOW', 0, create=True), \
             mock.patch.object(m.os, 'O_NONBLOCK', 0, create=True), \
             mock.patch.object(m.os, 'O_CLOEXEC', 0, create=True), \
             mock.patch.object(m.os, 'open', return_value=99), mock.patch.object(m.os, 'close'), \
             mock.patch.object(m.os, 'fstat', return_value=meta), \
             mock.patch.object(m, 'BOOT_ID', types.SimpleNamespace(read_text=lambda **kwargs:boot)):
            for fields in bad:
                with self.subTest(fields=fields), mock.patch.object(m.os, 'read', return_value=json.dumps(dict(base, **fields)).encode()):
                    with self.assertRaisesRegex(m.Refused, 'BAD_OWNERSHIP'): m.read_state(42)
            for fields in [{}, {'owner_kind':'C01_APP_DOWN_V1', 'owner_id':self.owner}]:
                with mock.patch.object(m.os, 'read', return_value=json.dumps(dict(base, **fields)).encode()):
                    self.assertEqual(m.read_state(42), dict(base, **fields))

    def test_competing_starts_serialize_on_shared_controller_lock(self):
        shared_lock = threading.Lock()
        current = []
        barrier = threading.Barrier(2)
        p = {'ActiveState':'active', 'SubState':'running', 'MainPID':'42', 'InvocationID':'d'*32}
        @contextlib.contextmanager
        def shared_locked():
            with shared_lock: yield 42
        def attempt(binding):
            barrier.wait()
            try: m.inject(binding=binding)
            except m.Refused as e: return str(e)
        def write(fd, state): current.append(dict(state))
        with mock.patch.object(m, 'locked', side_effect=shared_locked), \
             mock.patch.object(m, 'read_state', side_effect=lambda fd: current[-1] if current else None), \
             mock.patch.object(m, 'require_no_orphans'), mock.patch.object(m, 'service_identity', return_value=(p,'c'*64)), \
             mock.patch.object(m, 'ready', return_value=True), \
             mock.patch.object(m, 'install_helper', return_value=('helper-'+'e'*64+'.py','e'*64)), \
             mock.patch.object(m, 'write_state', side_effect=write), \
             mock.patch.object(m, 'arm_watchdog', side_effect=m.Refused('SIMULATED_INTERRUPT')), \
             mock.patch.object(m, 'BOOT_ID', types.SimpleNamespace(read_text=lambda **kwargs:'boot')):
            with ThreadPoolExecutor(max_workers=2) as ex:
                results = list(ex.map(attempt, [self.binding, ('f'*24, '1'*32)]))
        self.assertCountEqual(results, ['SIMULATED_INTERRUPT', 'PREVIOUS_RUN_REQUIRES_RESET'])
        self.assertEqual(len(current), 1)

if __name__ == '__main__': unittest.main(verbosity=2)
