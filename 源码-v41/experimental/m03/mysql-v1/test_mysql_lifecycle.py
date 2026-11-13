import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import MagicMock, Mock, patch

# The candidate is Linux-only; substitute just the unavailable import so that
# pure state-machine tests can run on the Windows development host.
if sys.platform != 'linux':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
HERE = Path(__file__).resolve().parent

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

m = module('mysql_candidate', 'mysql_lifecycle.py')
p = module('probe_candidate', 'm03_vm_probe.py')
RID = '0123456789abcdef'
RUN = '0123456789abcdef01234567'
NAME = 'm03_' + RID
OWNER = {'run_id': RUN, 'db_id': RID, 'boot_id': 'boot', 'token': 'a' * 64}
OK = subprocess.CompletedProcess([], 0, b'1\n', b'')
ERR1040 = subprocess.CompletedProcess([], 1, b'', b'ERROR 1040 (08004): Too many connections')
ERR1045 = subprocess.CompletedProcess([], 1, b'', b'ERROR 1045 (28000): Access denied')

def state():
    return {'version': 1, 'run_id': RID, 'phase': 'READY', 'primary_uuid': m.ZERO_UUID,
            'business_phase': 'M03_TEST_ONLY', 'boot_id': 'boot', 'uuids': {'source': 's', 'target': 't'},
            'attempted': []}

def make_drill():
    ctl = Mock()
    ctl.ENV = {}
    probe = Mock()
    probe.MARKER = p.MARKER
    probe.bounded_limit.side_effect = p.bounded_limit
    probe.is_1040.side_effect = p.is_1040
    probe.one_client.return_value = OK
    probe.query.side_effect = lambda _c, _r, _s, sql: (
        '2' if sql == 'SELECT @@global.max_connections' else
        '0\t0' if sql == 'SELECT @@global.general_log,@@global.log_bin' else
        'sha2_cache_cleaner\tAUDIT\tACTIVE\tBUILTIN\nmysqlx_cache_cleaner\tAUDIT\tACTIVE\tBUILTIN' if 'information_schema.plugins' in sql else
        'GRANT USAGE ON *.* TO `' + NAME + '`@`localhost`' if sql.startswith('SHOW GRANTS') else '0')
    return m.MySQLDrill(ctl, probe, RID, Path('ignored'), state()), ctl, probe

class LifecycleTests(unittest.TestCase):
    def test_prepare_persists_intent_before_secret_create_and_limits_grants(self):
        drill, ctl, probe = make_drill()
        snapshots = []
        ctl.save.side_effect = lambda _d, obj: snapshots.append(copy.deepcopy(obj))
        def create(*_args):
            self.assertEqual(snapshots[-1]['m03_probe']['phase'], 'CREATE_ATTEMPTED')
            self.assertEqual(snapshots[-1]['m03_probe']['holders_state'], 'NONE')
        with patch.object(m, 'option_fd', return_value=7), patch.object(m, 'mysql_sql_stdin', side_effect=create):
            drill.prepare()
        self.assertEqual((drill.phase, drill.count), ('READY', 2))
        self.assertNotIn('password', repr(snapshots))
        self.assertEqual(probe.one_client.call_count, 1)

    def test_logging_and_audit_checks_fail_before_account_creation(self):
        for bad in ('logging', 'audit'):
            drill, _, probe = make_drill()
            old = probe.query.side_effect
            def query(c, r, s, sql):
                if bad == 'logging' and 'general_log' in sql:
                    return '1\t0'
                if bad == 'audit' and 'information_schema.plugins' in sql:
                    return 'audit_log\tAUDIT\tACTIVE\tDYNAMIC'
                return old(c, r, s, sql)
            probe.query.side_effect = query
            with self.subTest(bad=bad), patch.object(m, 'option_fd') as fd, \
                 patch.object(m, 'mysql_sql_stdin') as create, self.assertRaises(m.Refused):
                drill.prepare()
            fd.assert_not_called()
            create.assert_not_called()

    def test_fault_and_recovery_require_real_mysql_outcomes(self):
        drill, ctl, probe = make_drill()
        drill.phase, drill.count, drill.fd = 'FAULT', 2, 7
        drill.holders = [Mock(), Mock()]
        for holder in drill.holders:
            holder.poll.return_value = None
        probe.sleepers.side_effect = [2, 2]
        probe.one_client.return_value = ERR1040
        self.assertEqual(drill.check()['mysql_error'], 1040)
        self.assertEqual(drill.check.__name__, 'check')
        probe.sleepers.side_effect = [2, 2]
        probe.one_client.return_value = ERR1045
        with self.assertRaises(m.Refused):
            drill.check()
        drill.phase = 'RELEASED'
        probe.sleepers.side_effect = [0, 0]
        probe.one_client.return_value = OK
        self.assertEqual(drill.check()['status'], 'RECOVERED')
        probe.sleepers.side_effect = [0, 0]
        probe.one_client.return_value = ERR1045
        with self.assertRaises(m.Refused):
            drill.check()

    def test_inject_marks_holders_uncertain_before_launch_and_confirms_1040(self):
        drill, ctl, probe = make_drill()
        drill.phase, drill.count, drill.fd = 'READY', 2, 7
        drill.state['m03_probe'] = {'phase': 'READY', 'holders_state': 'NONE'}
        snapshots = []
        ctl.save.side_effect = lambda _d, obj: snapshots.append(copy.deepcopy(obj))
        probe.is_1040.side_effect = p.is_1040
        probe.one_client.return_value = ERR1040
        probe.client_option_fd.side_effect = lambda _: __import__('contextlib').nullcontext(11)
        probe.client_args.return_value = ['/usr/bin/mysql', '--protocol=SOCKET', '--socket=/isolated/mysql.sock']
        def launch(*args, **kwargs):
            self.assertEqual(snapshots[-1]['m03_probe']['holders_state'], 'MAY_EXIST')
            self.assertEqual(kwargs['pass_fds'], (11,))
            self.assertNotIn('password', repr(args))
            return Mock()
        with patch.object(m.subprocess, 'Popen', side_effect=launch) as popen:
            drill.inject()
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(drill.phase, 'FAULT')
        self.assertEqual(snapshots[-1]['m03_probe']['phase'], 'FAULT')

    def test_wrong_injection_error_does_not_claim_fault(self):
        drill, _, probe = make_drill()
        drill.phase, drill.count, drill.fd = 'READY', 1, 7
        drill.state['m03_probe'] = {}
        probe.client_option_fd.return_value = __import__('contextlib').nullcontext(11)
        probe.client_args.return_value = ['/usr/bin/mysql']
        probe.one_client.return_value = ERR1045
        with patch.object(m.subprocess, 'Popen', return_value=Mock()), self.assertRaises(m.Refused):
            drill.inject()
        self.assertEqual(drill.phase, 'UNCERTAIN')
        self.assertEqual(drill.state['m03_probe']['holders_state'], 'MAY_EXIST')

    def test_resolve_closes_holders_before_confirming_connection(self):
        drill, ctl, probe = make_drill()
        drill.phase, drill.count, drill.fd = 'FAULT', 2, 7
        drill.state['m03_probe'] = {'holders_state': 'MAY_EXIST'}
        probe.one_client.return_value = OK
        drill.resolve()
        self.assertEqual(drill.phase, 'RELEASED')
        self.assertEqual(drill.state['m03_probe']['holders_state'], 'CLOSED')
        probe.stop_holders.assert_called_once()
        probe.wait_sleepers.assert_called_once()
        self.assertGreaterEqual(ctl.save.call_count, 3)

    def test_launch_failure_does_not_claim_holders_cleaned(self):
        drill, _, probe = make_drill()
        drill.phase, drill.count, drill.fd = 'READY', 1, None
        drill.state['m03_probe'] = {'holders_state': 'NONE'}
        probe.client_option_fd.return_value = __import__('contextlib').nullcontext(11)
        probe.client_args.return_value = ['/usr/bin/mysql']
        with patch.object(m.subprocess, 'Popen', side_effect=OSError('launch unknown')):
            with self.assertRaises(OSError):
                drill.inject()
        with self.assertRaises(m.Refused):
            drill.close_holders()
        self.assertEqual(drill.state['m03_probe']['holders_state'], 'MAY_EXIST')

    def test_account_cleanup_only_for_owned_target_and_checks_absence(self):
        ctl, probe, s = Mock(), Mock(), state()
        s['m03_probe'] = {'account': NAME}
        probe.query.side_effect = ['', '0']
        m.cleanup_account(ctl, probe, RID, s)
        probe.target.assert_called_once_with(ctl, RID, s)
        self.assertEqual(s['m03_probe']['phase'], 'ACCOUNT_REMOVED')
        self.assertIn('DROP USER IF EXISTS', probe.query.call_args_list[0].args[3])
        s['m03_probe']['account'] = 'another'
        with self.assertRaises(m.Refused):
            m.cleanup_account(ctl, probe, RID, s)
        self.assertEqual(probe.query.call_count, 2)

class SecretAndSafetyTests(unittest.TestCase):
    def test_plugin_policy_allows_only_known_builtin_audit_helpers(self):
        base = ('sha2_cache_cleaner\tAUDIT\tACTIVE\tBUILTIN\n'
                'mysqlx_cache_cleaner\tAUDIT\tACTIVE\tBUILTIN\n'
                'InnoDB\tSTORAGE ENGINE\tACTIVE\tBUILTIN')
        m.verify_plugin_inventory(base)
        for row in ('unknown\tAUDIT\tACTIVE\tBUILTIN',
                    'sha2_cache_cleaner\tAUDIT\tACTIVE\tDYNAMIC',
                    'audit_log\tAUDIT\tACTIVE\tDYNAMIC',
                    'extra\tDAEMON\tDISABLED\tDYNAMIC',
                    'other_audit\tDAEMON\tACTIVE\tBUILTIN',
                    'mysqlx_cache_cleaner\tDAEMON\tACTIVE\tBUILTIN',
                    'unknown\tAUDIT\tDELETING\tBUILTIN',
                    'broken\tAUDIT\tACTIVE'):
            with self.subTest(row=row), self.assertRaises(m.Refused):
                m.verify_plugin_inventory(row)
        with self.assertRaises(m.Refused):
            m.verify_plugin_inventory('')

    def test_diagnostic_records_only_whitelisted_stage_and_category(self):
        records = []
        with patch.object(m, 'save', side_effect=lambda _p, obj: records.append(obj.copy())):
            diagnostic = m.Diagnostic(Path('ignored'))
            diagnostic.advance('PREPARE_CREATE')
            diagnostic.fail(RuntimeError('password=secret SELECT private FROM customer'))
            diagnostic.advance('CLEANUP_INSTANCES')
            diagnostic.fail(OSError('more private data'))
        self.assertEqual(records[-1], {'stage': 'PREPARE_CREATE', 'error': 'RuntimeError'})
        self.assertNotIn('secret', repr(records))
        self.assertNotIn('SELECT', repr(records))

    def test_diagnostic_read_rejects_unexpected_or_extra_fields(self):
        for obj in ({'stage': 'PREPARE_CREATE', 'error': 'SQL secret'},
                    {'stage': 'SQL secret', 'error': 'Refused'},
                    {'stage': 'PREPARE_CREATE', 'error': 'Refused', 'detail': 'secret'}):
            with self.subTest(obj=obj), patch.object(m, 'load', return_value=obj):
                self.assertIsNone(m.read_diagnostic(Path('ignored')))
        with patch.object(m, 'load', return_value={'stage':'PREPARE_CREATE','error':'Refused'}):
            self.assertEqual(m.read_diagnostic(Path('ignored')),
                             {'stage':'PREPARE_CREATE','error':'Refused'})

    def test_dependency_startup_failure_reports_stage_without_message(self):
        records = []
        with patch.object(m, 'run_directory', return_value=Path('ignored')), \
             patch.object(m, 'owner_for', return_value=OWNER), patch.object(m, 'boot_id', return_value='boot'), \
             patch.object(m, 'proc_start', return_value=50), patch.object(m, 'save_once'), \
             patch.object(m, 'save', side_effect=lambda _p, obj: records.append(obj.copy())), \
             patch.object(m, 'load_dependencies', side_effect=RuntimeError('password=secret')):
            with self.assertRaises(RuntimeError):
                m.worker(RUN)
        self.assertEqual(records[-1], {'stage':'DEPENDENCIES', 'error':'RuntimeError'})
        self.assertNotIn('secret', repr(records))

    def test_start_failure_records_first_stage_and_still_attempts_cleanup(self):
        ctl, probe = Mock(), Mock()
        ctl.BASE = MagicMock()
        ctl.boot_context.return_value = ('boot', 100)
        ctl.start.side_effect = RuntimeError('SELECT secret')
        ctl.reset.side_effect = lambda _r, _d, value: value.update(phase='STOPPED')
        records = []
        with patch.object(m, 'run_directory', return_value=Path('ignored')), \
             patch.object(m, 'owner_for', return_value=OWNER), patch.object(m, 'boot_id', return_value='boot'), \
             patch.object(m, 'proc_start', return_value=50), patch.object(m, 'save_once'), \
             patch.object(m, 'save', side_effect=lambda _p, obj: records.append(obj.copy())), \
             patch.object(m, 'load_dependencies', return_value=(ctl, probe)), \
             patch.object(m, 'acquire_lock', return_value=9), patch.object(m.os, 'close'), \
             patch.object(m.signal, 'signal'), patch.object(m.signal, 'setitimer', create=True), \
             patch.object(m.signal, 'SIGALRM', 14, create=True), \
             patch.object(m.signal, 'ITIMER_REAL', 0, create=True), \
             patch.object(m, 'cleanup_account'), patch.object(m, 'write_receipt'):
            with self.assertRaises(RuntimeError):
                m.worker(RUN)
        ctl.reset.assert_called_once()
        self.assertEqual(records[-1], {'stage':'DB_START', 'error':'RuntimeError'})
        self.assertNotIn('secret', repr(records))

    def test_dependency_hashes_match_exact_source_bytes(self):
        self.assertEqual(set(m.DEPENDENCIES), {'m04_controller.py', 'm03_vm_probe.py'})
        for name, expected in m.DEPENDENCIES.items():
            with self.subTest(name=name):
                self.assertEqual(len(expected), 64)
                self.assertEqual(m.hashlib.sha256((HERE / name).read_bytes()).hexdigest(), expected)

    def test_create_secret_only_on_stdin_never_argv_or_captured_output(self):
        ctl, probe = Mock(), Mock()
        ctl.paths.return_value = (None, None, '/isolated/mysql.sock')
        secret = 'synthetic_secret_test_value'
        result = subprocess.CompletedProcess([], 0)
        with patch.object(m.subprocess, 'run', return_value=result) as run:
            m.mysql_sql_stdin(ctl, probe, RID, state(), 'CREATE USER ' + secret)
        args, kw = run.call_args
        self.assertNotIn(secret, repr(args[0]))
        self.assertIn(secret.encode(), kw['input'])
        self.assertIs(kw['stdout'], subprocess.DEVNULL)
        self.assertIs(kw['stderr'], subprocess.DEVNULL)
        self.assertIn('--protocol=SOCKET', args[0])
        self.assertIn('--socket=/isolated/mysql.sock', args[0])
        probe.target.assert_called_once()

    def test_other_ownership_or_primary_marker_is_rejected(self):
        for changes in ({'run_id': 'f' * 16}, {'business_phase': 'NEW'},
                        {'primary_uuid': 'primary'}, {'boot_id': 'other'}, {'replay_account': 'x'}):
            with self.subTest(changes=changes), self.assertRaises(m.Refused):
                m.state_belongs({**state(), **changes}, OWNER)
        m.state_belongs(state(), OWNER)

    def test_dead_worker_reset_never_confirms_untracked_holders(self):
        ctl, probe = Mock(), Mock()
        ctl.BASE = Path('ignored')
        s = state()
        s['m03_probe'] = {'account': NAME, 'holders_state': 'MAY_EXIST'}
        ctl.load.return_value = s
        ctl.reset.side_effect = lambda _r, _d, value: value.update(phase='STOPPED')
        with patch.object(m, 'boot_id', return_value='boot'), \
             patch.object(m, 'identity', return_value={'pid': 123, 'start': 50}), \
             patch.object(m, 'proc_start', side_effect=FileNotFoundError), \
             patch.object(m, 'acquire_lock', return_value=9), patch.object(m.os, 'close'), \
             patch.object(m, 'cleanup_account'), patch.object(m, 'load_dependencies', return_value=(ctl, probe)), \
             patch.object(m, 'write_receipt') as receipt, self.assertRaises(m.Refused):
            m.recover_stopped_worker(Path('ignored'), OWNER, ctl)
        ctl.reset.assert_called_once()
        receipt.assert_not_called()

    def test_live_worker_never_adopted_by_recovery(self):
        ctl = Mock()
        with patch.object(m, 'boot_id', return_value='boot'), \
             patch.object(m, 'identity', return_value={'pid': 123, 'start': 50}), \
             patch.object(m, 'proc_start', return_value=50), self.assertRaises(m.Refused):
            m.recover_stopped_worker(Path('ignored'), OWNER, ctl)
        ctl.setup.assert_not_called()

    def test_dead_worker_with_recorded_closed_holders_can_reset_owned_database(self):
        ctl, probe = Mock(), Mock()
        ctl.BASE = Path('ignored')
        s = state()
        s['m03_probe'] = {'account': NAME, 'holders_state': 'CLOSED'}
        ctl.load.return_value = s
        ctl.reset.side_effect = lambda _r, _d, value: value.update(phase='STOPPED')
        with patch.object(m, 'boot_id', return_value='boot'), \
             patch.object(m, 'identity', return_value={'pid': 123, 'start': 50}), \
             patch.object(m, 'proc_start', side_effect=FileNotFoundError), \
             patch.object(m, 'acquire_lock', return_value=9), patch.object(m.os, 'close'), \
             patch.object(m, 'cleanup_account') as cleanup, \
             patch.object(m, 'load_dependencies', return_value=(ctl, probe)), \
             patch.object(m, 'write_receipt') as receipt:
            m.recover_stopped_worker(Path('ignored'), OWNER, ctl)
        cleanup.assert_called_once()
        ctl.reset.assert_called_once()
        receipt.assert_called_once()

    def test_receipt_binds_original_owner_and_database(self):
        receipt = {'run_id': RUN, 'db_id': RID, 'boot_id': 'boot',
                   'owner_hash': m.hashlib.sha256(OWNER['token'].encode()).hexdigest(), 'status': 'STOPPED'}
        with patch.object(m, 'load', return_value=receipt):
            self.assertTrue(m.receipt_ok(Path('ignored'), OWNER))
        with patch.object(m, 'load', return_value={**receipt, 'db_id': 'f' * 16}):
            self.assertFalse(m.receipt_ok(Path('ignored'), OWNER))

    def test_alarm_during_accept_is_not_swallowed_as_socket_timeout(self):
        ctl, probe, server, drill = Mock(), Mock(), Mock(), Mock()
        ctl.BASE = MagicMock()
        ctl.boot_context.return_value = ('boot', 100)
        ctl.reset.side_effect = lambda _r, _d, value: value.update(phase='STOPPED')
        registered = []
        def set_handler(_sig, handler):
            registered.append(handler)
            return None
        def accept():
            registered[0](14, None)
        server.accept.side_effect = accept
        with patch.object(m, 'run_directory', return_value=Path('ignored')), \
             patch.object(m, 'owner_for', return_value=OWNER), patch.object(m, 'boot_id', return_value='boot'), \
             patch.object(m, 'proc_start', return_value=50), patch.object(m, 'save_once'), \
             patch.object(m, 'load_dependencies', return_value=(ctl, probe)), \
             patch.object(m, 'acquire_lock', return_value=9), patch.object(m.os, 'close'), \
             patch.object(m.os, 'chmod'), patch.object(m.signal, 'signal', side_effect=set_handler), \
             patch.object(m.signal, 'setitimer', create=True), \
             patch.object(m.signal, 'SIGALRM', 14, create=True), \
             patch.object(m.signal, 'ITIMER_REAL', 0, create=True), \
             patch.object(m, 'MySQLDrill', return_value=drill), \
             patch.object(m.socket, 'AF_UNIX', 1, create=True), \
             patch.object(m.socket, 'socket', return_value=server), patch.object(m, 'cleanup_account'), \
             patch.object(m, 'write_receipt') as receipt, self.assertRaises(TimeoutError):
            m.worker(RUN)
        ctl.reset.assert_called_once()
        receipt.assert_called_once()

if __name__ == '__main__':
    unittest.main()
