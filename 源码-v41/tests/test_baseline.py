import contextlib
import importlib.machinery
import importlib.util
import io
import os
import stat
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys

BASE = Path(__file__).resolve().parents[1] / 'baseline'
sys.path.insert(0, str(BASE))
import common


def load(name):
    loader = importlib.machinery.SourceFileLoader(name, str(BASE / name))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


deploy, verify = load('deploy'), load('verify')
real_trusted_tool = deploy.trusted_tool


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / 'systemd' / 'service.d'
        self.target.parent.mkdir()
        self.base = self.root / 'baseline'
        self.base.mkdir()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.project = self.root / 'project'
        (self.project / 'conf').mkdir(parents=True)
        (self.project / 'conf/30-stage3-reader.conf').write_bytes(deploy.STAGE)
        patches = [mock.patch.object(common, 'DROPINS', self.target),
                   mock.patch.object(common, 'BASELINE', self.base),
                   mock.patch.object(common, 'STATE', self.state),
                   mock.patch.object(common, 'PROJECT', self.project),
                   mock.patch.object(common, 'guard'), mock.patch.object(common, 'chain'),
                   mock.patch.object(deploy, 'trusted_tool'),
                   mock.patch.object(common, 'protected'), mock.patch.object(common, 'regular'),
                   mock.patch.object(common, 'command', return_value=(0, b'FragmentPath=/etc/systemd/system/orderguard-api.service\nLoadCredential=\nLoadCredentialEncrypted=\n')),
                   mock.patch.object(os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True)]
        if os.name == 'nt':
            patches.append(mock.patch.object(deploy.stat, 'S_IMODE', return_value=0o700))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def execute(self, apply):
        with contextlib.redirect_stdout(io.StringIO()):
            return deploy.run_plan(*deploy.prepare_plan(), apply)

    def test_dry_run_then_apply_then_idempotent(self):
        self.assertEqual(self.execute(False), 0)
        self.assertFalse(self.target.exists())
        self.assertEqual(self.execute(True), 0)
        stage = self.target / '30-stage3-reader.conf'
        before = stage.stat().st_mtime_ns
        self.assertEqual(stage.read_bytes(), deploy.STAGE)
        self.assertEqual((self.target / '40-baseline-legacy-credential.conf').read_bytes(), deploy.LEGACY)
        self.assertEqual(self.execute(True), 0)
        self.assertEqual(stage.stat().st_mtime_ns, before)

    def test_conflict_backup_no_overwrite_or_partial_create(self):
        self.target.mkdir()
        file = self.target / '30-stage3-reader.conf'
        file.write_bytes(b'local version')
        self.assertEqual(self.execute(False), 2)
        self.assertFalse((self.state / 'backups').exists())
        self.assertEqual(self.execute(True), 2)
        backups = list((self.state / 'backups').glob('*/30-stage3-reader.conf'))
        self.assertEqual([p.read_bytes() for p in backups], [b'local version'])
        self.assertEqual(file.read_bytes(), b'local version')
        self.assertFalse((self.target / '40-baseline-legacy-credential.conf').exists())

    def test_different_existing_credential_refuses(self):
        common.command.return_value = (0, b'FragmentPath=/etc/systemd/system/orderguard-api.service\nLoadCredential=mysql-password:/etc/elsewhere\n')
        with self.assertRaises(common.Refusal):
            deploy.prepare_plan()

    def test_same_loaded_credential_is_not_duplicated(self):
        common.command.return_value = (0, b'FragmentPath=/etc/systemd/system/orderguard-api.service\nLoadCredential=mysql-password:/etc/opsdrill/orderguard-app.password\n')
        _, plan = deploy.prepare_plan()
        self.assertEqual(plan['40-baseline-legacy-credential.conf'], 'configured')

    def test_verified_loaded_configuration_needs_no_new_dropin(self):
        self.target.mkdir()
        (self.target / 'existing.conf').write_text('[Service]\nLoadCredential=mysql-password:/etc/opsdrill/orderguard-app.password\n', encoding='utf-8')
        with mock.patch.object(deploy, 'already_configured', return_value=True):
            _, plan = deploy.prepare_plan()
        self.assertEqual(set(plan.values()), {'configured'})

    def test_verified_configuration_still_refuses_conflicting_target(self):
        self.target.mkdir()
        (self.target / '30-stage3-reader.conf').write_text('different', encoding='utf-8')
        with mock.patch.object(deploy, 'already_configured', return_value=True):
            targets, plan = deploy.prepare_plan()
        self.assertEqual(plan['30-stage3-reader.conf'], 'conflict')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.run_plan(targets, plan, False), 2)

    def test_pending_systemd_reload_does_not_skip_checks(self):
        common.command.return_value = (0, b'NeedDaemonReload=yes\n')
        self.assertFalse(deploy.already_configured())

    def test_other_dropin_reset_refused(self):
        self.target.mkdir()
        (self.target / 'unrelated.conf').write_text('[Service]\nLoadCredential=\nRestart=always\n', encoding='utf-8')
        with self.assertRaises(common.Refusal):
            deploy.prepare_plan()

    def test_untrusted_project_source_is_never_used_as_root_input(self):
        (self.project / 'conf/30-stage3-reader.conf').write_text('[Service]\nExecStart=evil\n')
        targets, _ = deploy.prepare_plan()
        self.assertEqual(targets['30-stage3-reader.conf'], deploy.STAGE)

    def test_untrusted_tool_is_refused(self):
        deploy.trusted_tool.side_effect = common.Refusal('untrusted')
        with self.assertRaises(common.Refusal):
            deploy.prepare_plan()

    def test_tool_guard_rejects_unsafe_script_file(self):
        common.regular.side_effect = common.Refusal('unsafe tool')
        with self.assertRaises(common.Refusal):
            real_trusted_tool()
        common.regular.assert_called_once()

    def test_backup_state_must_be_root_controlled(self):
        common.chain.side_effect = common.Refusal('unsafe state')
        with self.assertRaises(common.Refusal):
            deploy.state_dir()


class VerifyTests(unittest.TestCase):
    def test_mysql_listener_scope_and_identity(self):
        local=(b'LISTEN 0 151 127.0.0.1:3306 0.0.0.0:* users:(("mysqld",pid=123,fd=1))\n'
               b'LISTEN 0 70 127.0.0.1:33060 0.0.0.0:* users:(("mysqld",pid=123,fd=2))\n')
        def command(args,**kwargs):
            return (0,b'123\n') if args[0]=='systemctl' else (0,local)
        with mock.patch.object(common,'command',side_effect=command):
            self.assertEqual(verify.mysql_listeners()[0],'PASS')
        with mock.patch.object(common,'command',side_effect=[(0,b'123\n'),(0,local.replace(b'127.0.0.1:3306',b'*:3306',1))]):
            self.assertEqual(verify.mysql_listeners()[0],'FAIL')
        with mock.patch.object(common,'command',side_effect=[(0,b'123\n'),(0,local.replace(b'pid=123',b'pid=999'))]):
            self.assertEqual(verify.mysql_listeners()[0],'UNKNOWN')
        with mock.patch.object(common,'command',side_effect=[(0,b'123\n'),(0,b'')]):
            self.assertEqual(verify.mysql_listeners()[0],'FAIL')
        with mock.patch.object(common,'command',side_effect=[(0,b'123\n'),(None,b'')]):
            self.assertEqual(verify.mysql_listeners()[0],'UNKNOWN')

    def test_database_uses_fixed_query_and_never_prints_raw_output(self):
        secret = b'private-value-should-not-leak'
        calls = []
        def cmd(args, input_bytes=None, timeout=None):
            calls.append((args, input_bytes))
            return 1, secret
        with mock.patch.object(verify, 'check_admin_options'), mock.patch.object(common, 'command', side_effect=cmd):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                status, detail = verify.database()
                print(status, detail)
            self.assertEqual(status, 'UNKNOWN')
            self.assertNotIn(secret.decode(), out.getvalue())
            self.assertNotIn(secret.decode(), repr(calls))
            self.assertTrue(calls[0][0][1].startswith('--defaults-file='))
            self.assertIn(b'SELECT @@version', calls[0][1])
            self.assertNotIn(b'INSERT', calls[0][1])
            self.assertNotIn(b'DROP ', calls[0][1])

    def test_fixed_database_result_and_mismatch(self):
        with mock.patch.object(verify, 'check_admin_options'), \
             mock.patch.object(common, 'command', return_value=(0, b'8.4.6\t5\t500\t500000\t25000\t2\n')):
            self.assertEqual(verify.database()[0], 'PASS')
            common.command.return_value = (0, b'8.4.6\t5\t500\t499999\t25000\t2\n')
            self.assertEqual(verify.database()[0], 'FAIL')

    def test_valid_admin_file_does_not_put_password_in_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'admin.cnf'
            path.write_text('[client]\nhost=localhost\nuser=root\npassword=secret-%-for-test\n', encoding='utf-8')
            with mock.patch.object(common, 'ADMIN', path), mock.patch.object(common, 'protected'), \
                 mock.patch.object(common, 'command', return_value=(0, b'8.4.6\t5\t500\t500000\t25000\t2\n')) as cmd:
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                    status, detail = verify.database()
                    print(status, detail)
                self.assertEqual(status, 'PASS')
                self.assertNotIn('secret-%-for-test', repr(cmd.call_args) + out.getvalue())
                self.assertNotIn('localhost', out.getvalue())
                argv = cmd.call_args.args[0]
                self.assertIn('--protocol=SOCKET', argv)
                self.assertIn('--socket=/var/lib/mysql/mysql.sock', argv)
                self.assertIn('--host=localhost', argv)
                self.assertEqual(argv[1], '--defaults-file=' + str(path))

    def test_admin_options_allow_only_supported_hosts_and_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'admin.cnf'
            with mock.patch.object(common, 'ADMIN', path), mock.patch.object(common, 'protected'), \
                 mock.patch.object(common, 'command', return_value=(0, b'8.4.6\t5\t500\t500000\t25000\t2\n')) as mysql:
                for index, host in enumerate(('localhost', '127.0.0.1', '"localhost"')):
                    with self.subTest(allowed=True, case=index):
                        path.write_text('[client]\nuser=root\npassword=secret-test\nhost=' + host + '\nsocket=/var/lib/mysql/mysql.sock\nprotocol=SOCKET\n', encoding='utf-8')
                        self.assertEqual(verify.database()[0], 'PASS')
                path.write_text('[client]\nuser=root\npassword=secret-test\n', encoding='utf-8')
                self.assertEqual(verify.database()[0], 'PASS')
                bad_configs = [
                    '[client]\nuser=root\npassword=secret-test\nhost=::1\n',
                    '[client]\nuser=root\npassword=secret-test\nhost=example.invalid\n',
                    '[client]\nuser=root\npassword=secret-test\ninit-command=DROP DATABASE x\n',
                    '[client]\nuser=root\npassword=secret-test\n!include /tmp/file\n',
                    '[client]\nuser=root\npassword=secret-test\n[mysql]\n',
                    '[DEFAULT]\n[client]\nuser=root\npassword=secret-test\n',
                    '[client]\nuser=root\npassword=secret-test\nhost=localhost\nhost=127.0.0.1\n',
                    '[client]\nuser=root\npassword=secret-test\\\n continuation\n',
                    '[client]\nuser=root\npassword=secret-test\nsocket=/tmp/other.sock\n',
                    '[client]\nuser=root\npassword=secret-test\nprotocol=TCP\n',
                    '[client]\npassword=secret-test\nhost=localhost\n',
                    '[client]\nuser=root\npassword=secret-test\x00\n',
                ]
                for config in bad_configs:
                    with self.subTest(rejected=True):
                        path.write_text(config, encoding='utf-8')
                        mysql.reset_mock()
                        out = io.StringIO()
                        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                            status, detail = verify.database()
                            print(status, detail)
                        self.assertEqual(status, 'UNKNOWN')
                        mysql.assert_not_called()
                        self.assertNotIn('secret-test', out.getvalue())
                        self.assertNotIn('example.invalid', out.getvalue())

    def test_admin_parser_exception_does_not_echo_secret(self):
        with mock.patch.object(verify, 'check_admin_options', side_effect=RuntimeError('private-exception-value')), \
             mock.patch.object(common, 'command') as mysql:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                status, detail = verify.database()
                print(status, detail)
            self.assertEqual(status, 'UNKNOWN')
            mysql.assert_not_called()
            self.assertNotIn('private-exception-value', out.getvalue())

    def test_mysql_client_exception_does_not_echo_secret(self):
        with mock.patch.object(verify, 'check_admin_options'), \
             mock.patch.object(common, 'command', side_effect=RuntimeError('private-client-value')):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                status, detail = verify.database()
                print(status, detail)
            self.assertEqual(status, 'UNKNOWN')
            self.assertNotIn('private-client-value', out.getvalue())

    def test_http_response_is_checked_without_printing_body(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'{"status":"ok","secret":"private-response"}'
        opener = mock.Mock()
        opener.open.return_value = response
        out = io.StringIO()
        with mock.patch.object(verify.urllib.request, 'build_opener', return_value=opener), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            self.assertTrue(verify.http('/health', lambda data: data.get('status') == 'ok'))
        self.assertNotIn('private-response', out.getvalue())
        opener.open.assert_called_once_with('http://127.0.0.1:8080/health', timeout=4)

    def test_credential_check_requires_exact_mapping(self):
        out = (b'User=devops\nGroup=devops\nWorkingDirectory=/opt/ops-drill-kit\n'
               b'FragmentPath=/etc/systemd/system/orderguard-api.service\n'
               b'ExecStart=/opt/ops-drill-kit/.venv/bin/python app.main:app 127.0.0.1 8000\n'
               b'LoadCredential=mysql-password:/etc/opsdrill/orderguard-app.password-evil '
               b'stage3-reader-password:/etc/opsdrill/orderguard-stage3-reader.password\n'
               b'Environment=STAGE3_MYSQL_SOCKET=/var/lib/mysql/mysql.sock\n')
        with mock.patch.object(common, 'command', return_value=(0, out)), \
             mock.patch.object(common, 'chain'), mock.patch.object(common, 'regular'), \
             mock.patch.object(common, 'PROJECT', '/opt/ops-drill-kit'):
            self.assertEqual(verify.credential_settings(), 'FAIL')
            common.command.return_value = (0, out.replace(b'password-evil', b'password'))
            self.assertEqual(verify.credential_settings(), 'PASS')

    def test_unprintable_credential_uses_unit_files(self):
        out = (b'User=devops\nGroup=devops\nWorkingDirectory=/opt/ops-drill-kit\n'
               b'FragmentPath=/etc/systemd/system/orderguard-api.service\nNeedDaemonReload=no\n'
               b'DropInPaths=/etc/systemd/system/orderguard-api.service.d/a.conf\n'
               b'ExecStart=/opt/ops-drill-kit/.venv/bin/python app.main:app 127.0.0.1 8000\n'
               b'LoadCredential=[unprintable]\nEnvironment=STAGE3_MYSQL_SOCKET=/var/lib/mysql/mysql.sock\n')
        expected = {b'mysql-password': b'mysql-password:/etc/opsdrill/orderguard-app.password',
                    b'stage3-reader-password': b'stage3-reader-password:/etc/opsdrill/orderguard-stage3-reader.password'}
        with mock.patch.object(common, 'command', return_value=(0, out)), \
             mock.patch.object(common, 'chain'), mock.patch.object(common, 'regular'), \
             mock.patch.object(common, 'PROJECT', '/opt/ops-drill-kit'), \
             mock.patch.object(verify, 'unit_credentials', return_value=(expected, {})) as unit:
            self.assertEqual(verify.credential_settings(), 'PASS')
            self.assertEqual(len(unit.call_args.args[0]), 2)
            common.command.return_value = (0, out.replace(b'NeedDaemonReload=no', b'NeedDaemonReload=yes'))
            self.assertEqual(verify.credential_settings(), 'UNKNOWN')
            common.command.return_value = (0, out.replace(b'DropInPaths=/etc/systemd/system/orderguard-api.service.d/a.conf', b'DropInPaths=[unprintable]'))
            self.assertEqual(verify.credential_settings(), 'UNKNOWN')
            common.command.return_value = (0, out)
            unit.side_effect = common.Refusal('unsafe path')
            self.assertEqual(verify.credential_settings(), 'UNKNOWN')
            unit.side_effect = None
            unit.return_value = ({b'mysql-password': b'mysql-password:/different'}, {})
            self.assertEqual(verify.credential_settings(), 'FAIL')
            unit.return_value = (expected, {b'mysql-password': b'mysql-password:/encrypted'})
            self.assertEqual(verify.credential_settings(), 'UNKNOWN')

    def test_unit_files_are_merged_and_resets_applied_without_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unit, dropin = root / 'unit', root / 'dropin'
            unit.write_bytes(b'[Service]\nLoadCredential=old:/old\nEnvironment=SECRET=private-value\n')
            dropin.write_bytes(b'[Service]\nLoadCredential=\nLoadCredential=mysql-password:/etc/opsdrill/orderguard-app.password\nLoadCredential=stage3-reader-password:/etc/opsdrill/orderguard-stage3-reader.password\n')
            output = io.StringIO()
            with mock.patch.object(common, 'chain'), mock.patch.object(common, 'regular'), \
                 contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                found, encrypted = verify.unit_credentials([unit, dropin])
            self.assertNotIn(b'old', found)
            self.assertEqual(len(found), 2)
            self.assertEqual(encrypted, {})
            self.assertNotIn('private-value', output.getvalue())
            dropin.write_bytes(b'[Service]\nLoadCredential=abc:/path\\\n next\n')
            with mock.patch.object(common, 'chain'), mock.patch.object(common, 'regular'):
                with self.assertRaises(verify.Unverifiable):
                    verify.unit_credentials([unit, dropin])

    def test_admin_options_require_protected_file(self):
        with mock.patch.object(common, 'protected', side_effect=common.Refusal('unsafe')), \
             mock.patch.object(common, 'command') as mysql:
            status, _ = verify.database()
        self.assertEqual(status, 'UNKNOWN')
        mysql.assert_not_called()

    def test_no_service_or_http_without_lab_guard(self):
        out = io.StringIO()
        with mock.patch.object(verify, 'os_version', return_value=True), \
             mock.patch.object(common, 'vm_ok', return_value=False), \
             mock.patch.object(common, 'marker_ok', return_value=True), \
             mock.patch.object(verify, 'http') as http, \
             mock.patch.object(verify, 'database') as database, contextlib.redirect_stdout(out):
            self.assertEqual(verify.main([]), 2)
            http.assert_not_called()
            database.assert_not_called()

    def test_directory_and_file_guards_reject_unsafe_metadata(self):
        fake = mock.Mock()
        fake.lstat.return_value = mock.Mock(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        with self.assertRaises(common.Refusal):
            common.directory(fake)
        fake.lstat.return_value = mock.Mock(st_mode=stat.S_IFDIR | 0o775, st_uid=0)
        with self.assertRaises(common.Refusal):
            common.directory(fake)
        fake.lstat.return_value = mock.Mock(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=2)
        with self.assertRaises(common.Refusal):
            common.regular(fake, private=True)

    def test_nonroot_project_owner_is_reported_not_rejected(self):
        devops_dir = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=1000, st_nlink=1)
        devops_file = mock.Mock(st_mode=stat.S_IFREG | 0o644, st_uid=1000, st_gid=1000, st_nlink=1)
        def metadata(path):
            return devops_dir if path.suffix == '' else devops_file
        with mock.patch.object(common, 'observed_chain'), \
             mock.patch.object(Path, 'lstat', autospec=True, side_effect=metadata):
            missing, records = verify.has_files()
        self.assertEqual(missing, [])
        self.assertTrue(any(st.st_uid == 1000 for st in records.values()))
        detail = verify.owner_text(devops_file)
        self.assertIn('uid=1000', detail)
        self.assertIn('gid=1000', detail)
        self.assertIn('mode=0644', detail)
        self.assertIn('不作为 root 可信输入', detail)

    def test_observed_directory_accepts_devops_but_rejects_symlink(self):
        root = Path('/a')
        devops_dir = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=1000)
        link = mock.Mock(st_mode=stat.S_IFLNK | 0o777, st_uid=1000)
        with mock.patch.object(Path, 'lstat', return_value=devops_dir):
            common.observed_chain(root)
        with mock.patch.object(Path, 'lstat', return_value=link):
            with self.assertRaises(common.Refusal):
                common.observed_chain(root)

    def test_root_write_input_rejects_nonroot_file(self):
        fake = mock.Mock()
        fake.lstat.return_value = mock.Mock(st_mode=stat.S_IFREG | 0o644, st_uid=1000, st_gid=1000, st_nlink=1)
        with self.assertRaises(common.Refusal):
            common.regular(fake)

    def test_guard_accepts_nonroot_project_directories(self):
        with mock.patch.object(common.os, 'geteuid', return_value=0, create=True), \
             mock.patch.object(common, 'marker_ok', return_value=True), \
             mock.patch.object(common, 'vm_ok', return_value=True), \
             mock.patch.object(common, 'observed_chain') as observed, \
             mock.patch.object(common, 'chain') as root_chain:
            common.guard()
        self.assertEqual([call.args[0] for call in observed.call_args_list], [common.PROJECT, common.BASELINE])
        root_chain.assert_not_called()

    def test_venv_info_only_observes_nonroot_venv(self):
        directory = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=1000, st_nlink=1)
        link = mock.Mock(st_mode=stat.S_IFLNK | 0o777, st_uid=1000, st_gid=1000, st_nlink=1)
        target = mock.Mock(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0, st_nlink=1)
        resolved = Path('/usr/bin/python3')
        def metadata(path):
            if path == resolved:
                return target
            if path.name == 'python':
                return link
            return directory
        with mock.patch.object(common, 'observed_chain'), \
             mock.patch.object(Path, 'lstat', autospec=True, side_effect=metadata), \
             mock.patch.object(Path, 'resolve', return_value=resolved), \
             mock.patch.object(os, 'access', return_value=True), \
             mock.patch.object(common, 'command') as command:
            ok, records = verify.venv_info()
        self.assertTrue(ok)
        self.assertEqual(records[0][1].st_uid, 1000)
        command.assert_not_called()

    def test_verify_does_not_fail_only_for_devops_owned_project(self):
        project_dir = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=1000, st_nlink=1)
        project_file = mock.Mock(st_mode=stat.S_IFREG | 0o644, st_uid=1000, st_gid=1000, st_nlink=1)
        records = {Path('/opt/ops-drill-kit'): project_dir, Path('/opt/ops-drill-kit/app/main.py'): project_file}
        def command(args, **kwargs):
            return (0, b'Enforcing\n') if args == ['getenforce'] else (0, b'')
        with mock.patch.object(common.os, 'geteuid', return_value=0, create=True), \
             mock.patch.object(verify, 'os_version', return_value=True), \
             mock.patch.object(common, 'vm_ok', return_value=True), \
             mock.patch.object(common, 'marker_ok', return_value=True), \
             mock.patch.object(verify, 'has_files', return_value=([], records)), \
             mock.patch.object(verify, 'venv_info', return_value=(True, [])), \
             mock.patch.object(common, 'protected'), \
             mock.patch.object(verify, 'credential_settings', return_value='PASS'), \
             mock.patch.object(verify, 'mysql_listeners', return_value=('PASS', 'ok')), \
             mock.patch.object(common, 'command', side_effect=command), \
             mock.patch.object(verify, 'http', return_value=True), \
             mock.patch.object(verify, 'database', return_value=('PASS', 'ok')):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(verify.main([]), 0)
            self.assertIn('uid=1000', out.getvalue())
            self.assertIn('不作为 root 可信输入', out.getvalue())
            project_file.st_mode = stat.S_IFREG | 0o666
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(verify.main([]), 2)


if __name__ == '__main__':
    unittest.main()
