import subprocess
import sys
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

source = Path(__file__).resolve().parent
if not (source / 'l01_logrotate.py').exists():
    source = Path(__file__).resolve().parents[2] / 'drills/linux/L01'
sys.path.insert(0, str(source))
import l01_logrotate as policy

GOOD = b'''/var/log/nginx/*.log {
    daily
    rotate 10
    postrotate
        /bin/kill -USR1 `cat /run/nginx.pid 2>/dev/null` 2>/dev/null || true
    endscript
}
'''
NGINX = '''access_log /var/log/nginx/orderguard-access.log;
error_log /var/log/nginx/orderguard-error.log warn;
'''
DEBUG = '''rotating pattern: /var/log/nginx/*.log  forced from command line (10 rotations)
considering log /var/log/nginx/orderguard-access.log
considering log /var/log/nginx/orderguard-error.log
'''


class RotationPolicyTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, 'protected configuration checks require root')
    def test_rejects_writable_symlink_and_hardlink_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'nginx'
            path.write_bytes(GOOD)
            path.chmod(0o666)
            with mock.patch.object(policy, 'POLICY', path):
                with self.assertRaisesRegex(policy.PolicyError, 'UNSAFE_LOGROTATE_CONFIG'):
                    policy.read_policy()
                path.chmod(0o644)
                link = Path(directory) / 'hardlink'
                os.link(path, link)
                with self.assertRaisesRegex(policy.PolicyError, 'UNSAFE_LOGROTATE_CONFIG'):
                    policy.read_policy()
                link.unlink()
                self.assertEqual(policy.read_policy()[0], GOOD)
                symlink = Path(directory) / 'symlink'
                symlink.symlink_to(path)
                with mock.patch.object(policy, 'POLICY', symlink), self.assertRaises(OSError):
                    policy.read_policy()

    def test_real_policy_scope_and_reopen_are_required(self):
        policy.validate_policy(GOOD)
        for bad in (GOOD.replace(b'/var/log/nginx/*.log', b'/var/log/other/*.log'),
                    GOOD.replace(b'rotate 10', b'rotate 0'),
                    GOOD.replace(b'/bin/kill -USR1', b'# /bin/kill -USR1'),
                    GOOD.replace(b'daily', b'notifempty')):
            with self.subTest(policy=bad), self.assertRaises(policy.PolicyError):
                policy.validate_policy(bad)

    def test_both_active_nginx_paths_must_be_covered(self):
        policy.validate_output(NGINX, DEBUG)
        with self.assertRaisesRegex(policy.PolicyError, 'NGINX_LOG_TARGET_MISSING'):
            policy.validate_output(NGINX.replace('access_log', '# access_log'), DEBUG)
        with self.assertRaisesRegex(policy.PolicyError, 'LOGROTATE_TARGET_MISSING'):
            policy.validate_output(NGINX, DEBUG.replace('orderguard-error.log', 'other.log'))

    def test_debug_only_and_changed_config_refused(self):
        identity = (1, 2, len(GOOD), 3)
        answers = [subprocess.CompletedProcess([], 0, NGINX, ''),
                   subprocess.CompletedProcess([], 0, '', DEBUG)]
        with mock.patch.object(policy, 'read_policy', side_effect=[(GOOD, identity), (GOOD, identity)]), \
             mock.patch.object(policy.subprocess, 'run', side_effect=answers) as run:
            policy.verify()
            command = run.call_args_list[1].args[0]
            self.assertIn('--debug', command)
            self.assertEqual(command[command.index('--state') + 1], '/dev/null')
        with mock.patch.object(policy, 'read_policy', side_effect=[(GOOD, identity), (GOOD + b'\n', identity)]), \
             mock.patch.object(policy.subprocess, 'run', side_effect=answers):
            with self.assertRaisesRegex(policy.PolicyError, 'LOGROTATE_CONFIG_CHANGED'):
                policy.verify()

    def test_failed_syntax_cannot_pass(self):
        answers = [subprocess.CompletedProcess([], 0, NGINX, ''),
                   subprocess.CompletedProcess([], 1, '', 'invalid')]
        with mock.patch.object(policy, 'read_policy', return_value=(GOOD, (1, 2, 3, 4))), \
             mock.patch.object(policy.subprocess, 'run', side_effect=answers):
            with self.assertRaisesRegex(policy.PolicyError, 'LOGROTATE_CONFIG_INVALID'):
                policy.verify()


if __name__ == '__main__':
    unittest.main(verbosity=2)
