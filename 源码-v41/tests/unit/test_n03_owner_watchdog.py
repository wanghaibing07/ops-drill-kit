import contextlib
import importlib.util
import io
import pathlib
import sys
import types
import unittest
from unittest import mock

path = pathlib.Path(__file__).resolve().parents[2] / 'experimental/n03-c01/n03_502.py'
spec = importlib.util.spec_from_file_location('n03_owner_watchdog', path)
m = importlib.util.module_from_spec(spec)
try:
    import fcntl
except ImportError:
    # Scope the Windows-only stub to this import; do not affect other suites.
    with mock.patch.dict(sys.modules, {'fcntl': types.SimpleNamespace()}):
        spec.loader.exec_module(m)
else:
    spec.loader.exec_module(m)

class WatchdogBindingTests(unittest.TestCase):
    def setUp(self):
        self.rid, self.owner = 'a' * 24, 'b' * 32
        self.state = {'kind': 'n03-502', 'run_id': self.rid, 'phase': 'FAULT',
                      'timer': 'opsdrill-n03-recover-' + self.rid + '.timer',
                      'owner_kind': 'C01_APP_DOWN_V1', 'owner_id': self.owner}
        for name, value in [('guard', None), ('locked', contextlib.nullcontext(42)),
                            ('read_state', self.state)]:
            patch = mock.patch.object(m, name, return_value=value)
            patch.start(); self.addCleanup(patch.stop)

    def test_matching_watchdog_recovers_and_records(self):
        with mock.patch.object(m, 'helper_verified'), mock.patch.object(m, 'helper_path', return_value=m.CODE), \
             mock.patch.object(m, 'restore_service', return_value='STARTED') as restore, \
             mock.patch.object(m, 'write_state') as write, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.watchdog(self.rid, self.owner), 0)
            restore.assert_called_once_with(self.state)
            write.assert_called_once()
            self.assertEqual(self.state['phase'], 'WATCHDOG_HEALTHY')

    def test_wrong_or_missing_binding_has_no_effect_even_if_run_id_reused(self):
        with mock.patch.object(m, 'helper_verified') as helper, mock.patch.object(m, 'restore_service') as restore, \
             mock.patch.object(m, 'write_state') as write:
            for rid, owner in [(self.rid, None), (self.rid, 'c' * 32), ('d' * 24, self.owner)]:
                with self.subTest(rid=rid, owner=owner), self.assertRaises(m.Refused):
                    m.watchdog(rid, owner)
            helper.assert_not_called(); restore.assert_not_called(); write.assert_not_called()

    def test_legacy_unowned_watchdog_and_owned_watchdog_do_not_cross(self):
        self.state.pop('owner_kind'); self.state.pop('owner_id')
        with mock.patch.object(m, 'helper_verified'), mock.patch.object(m, 'helper_path', return_value=m.CODE), \
             mock.patch.object(m, 'restore_service', return_value='STARTED') as restore, \
             mock.patch.object(m, 'write_state'), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(m.Refused, 'C01_OWNER_MISMATCH'):
                m.watchdog(self.rid, self.owner)
            restore.assert_not_called()
            self.assertEqual(m.watchdog(self.rid), 0)
            restore.assert_called_once()

    def test_arm_and_service_identity_bind_the_same_arguments(self):
        with mock.patch.object(m, 'helper_verified'), mock.patch.object(m, 'require_watchdog_armed'), \
             mock.patch.object(m, 'run') as run, mock.patch.object(m, 'helper_path', return_value='/safe/helper'):
            m.arm_watchdog(self.state)
            args = list(run.call_args.args)
            self.assertEqual(args[-5:], ['/usr/bin/python3', '/safe/helper', 'watchdog', self.rid, self.owner])
            service = {'LoadState': 'loaded', 'FragmentPath': '/run/systemd/transient/' + self.state['timer'][:-6] + '.service',
                       'Type': 'exec', 'User': 'root', 'ExecStart': 'parsed below'}
            with mock.patch.object(m, 'parse_argv', return_value=('/usr/bin/python3', args[-5:])):
                self.assertTrue(m.verify_watchdog_service(self.state, service))
            for bad in [args[-5:-1], args[-5:-1] + ['c' * 32]]:
                with mock.patch.object(m, 'parse_argv', return_value=('/usr/bin/python3', bad)):
                    with self.assertRaisesRegex(m.Refused, 'WATCHDOG_IDENTITY'):
                        m.verify_watchdog_service(self.state, service)
            self.state.pop('owner_kind'); self.state.pop('owner_id')
            m.arm_watchdog(self.state)
            self.assertEqual(list(run.call_args.args)[-4:], ['/usr/bin/python3', '/safe/helper', 'watchdog', self.rid])
            with mock.patch.object(m, 'parse_argv', return_value=('/usr/bin/python3', args[-5:-1])):
                self.assertTrue(m.verify_watchdog_service(self.state, service))

    def test_cli_rejects_malformed_binding_and_routes_both_formats(self):
        with mock.patch.object(m, 'watchdog', return_value=0) as call:
            self.assertEqual(m.main(['n03', 'watchdog', self.rid]), 0)
            self.assertEqual(m.main(['n03', 'watchdog', self.rid, self.owner]), 0)
            self.assertEqual(call.call_args_list, [mock.call(self.rid), mock.call(self.rid, self.owner)])
            with self.assertRaisesRegex(m.Refused, 'USAGE'):
                m.main(['n03', 'watchdog', self.rid, self.owner, 'extra'])
        with self.assertRaisesRegex(m.Refused, 'BAD_C01_BINDING'):
            m.watchdog(self.rid, 'bad')

if __name__ == '__main__':
    unittest.main()