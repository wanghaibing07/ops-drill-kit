import contextlib
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))
    if not hasattr(os, 'O_NOFOLLOW'):
        os.O_NOFOLLOW = 0
import replay_integration as r

class IntegrationTests(unittest.TestCase):
    def test_audit_happens_before_account_creation_and_apply(self):
        actions=[]
        @contextlib.contextmanager
        def audit(*args):
            actions.append('audit')
            yield 55
            actions.append('close-stream')
        class Account:
            def apply(self, stream):
                self.stream=stream
                actions.append('apply')
        @contextlib.contextmanager
        def account(*args):
            actions.append('account')
            yield Account()
            actions.append('drop-account')
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'replay.sql')
            with open(path, 'wb') as f:
                f.write(b'fake')
            with patch.object(r.sealed_replay, 'audited_replay_stream', audit), patch.object(r.m04_replay_account, 'replay_account', account):
                r.audited_restricted_replay('0123456789abcdef', '.', {}, b'log', path, 4, 5, 6, (), 1, 2, 3, ['']*9)
        self.assertEqual(actions, ['audit','account','apply','drop-account','close-stream'])

    def test_invalid_row_refused_before_any_access(self):
        with self.assertRaises(r.ctl.SafetyError):
            r.audited_restricted_replay('0123456789abcdef', '.', {}, b'', 'absent', 4, 5, 6, (), 1, 2, 3, [])

    def test_audit_failure_never_creates_account(self):
        @contextlib.contextmanager
        def rejected(*args):
            raise ValueError('audit rejected')
            yield
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'replay.sql')
            with open(path, 'wb') as f:
                f.write(b'bad replay')
            with patch.object(r.sealed_replay, 'audited_replay_stream', rejected), \
                 patch.object(r.m04_replay_account, 'replay_account') as account:
                with self.assertRaisesRegex(ValueError, 'audit rejected'):
                    r.audited_restricted_replay('0123456789abcdef', '.', {}, b'log', path,
                                                4, 5, 6, (), 1, 2, 3, [''] * 9)
                account.assert_not_called()

if __name__ == '__main__':
    unittest.main()
