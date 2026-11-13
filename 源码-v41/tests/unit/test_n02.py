import importlib.util
import json
import pathlib
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('n02', pathlib.Path(__file__).resolve().parents[2] / 'drills/network/N02/n02.py')
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)


class CandidateTests(unittest.TestCase):
    def test_unowned_and_replaced_namespace_rejected(self):
        with patch.object(n, 'namespaces', return_value={'od-router'}), patch.object(n, 'inode', return_value=7):
            with self.assertRaises(n.Refused): n.validate_owned({'namespaces': {}})
            with self.assertRaises(n.Refused): n.validate_owned({'namespaces': {'od-router': 8}})

    def test_inject_scoped_and_duplicate_refused(self):
        calls = []
        state = {'baseline': 'x', 'injected': None, 'intent': False}
        with patch.object(n, 'verify_watchdog'), patch.object(n, 'check_table'), patch.object(n, 'table_digest', side_effect=['x', 'y']), patch.object(n, 'save'), patch.object(n, 'tagged_handles', return_value=[]), patch.object(n, 'ns', side_effect=lambda *a, **k: calls.append(a)):
            n.inject(state)
        args = calls[0]
        self.assertEqual(args[:7], ('od-router', n.NFT, 'insert', 'rule', 'inet', 'od', 'forward'))
        for value in ('"veth-rc"','"veth-rs"','10.203.1.2','10.203.2.2','8080','drop'):
            self.assertIn(value, args)
        with patch.object(n, 'verify_watchdog'), patch.object(n, 'check_table'), patch.object(n, 'tagged_handles', return_value=[10]), patch.object(n, 'ns') as mocked:
            with self.assertRaises(n.Refused): n.inject(state)
            mocked.assert_not_called()

    def test_repair_idempotent_and_ambiguous_refused(self):
        state = {'baseline':'x', 'injected':None}
        with patch.object(n, 'check_table'), patch.object(n, 'save'), patch.object(n, 'tagged_handles', return_value=[]), patch.object(n, 'ns') as mocked:
            n.repair(state); mocked.assert_not_called()
        with patch.object(n, 'tagged_handles', return_value=[2, 3]), patch.object(n, 'ns') as mocked:
            with self.assertRaises(n.Refused): n.repair(state)
            mocked.assert_not_called()

    def test_cleanup_refuses_process_before_deletion(self):
        result = subprocess.CompletedProcess([], 0, stdout='123\n')
        with patch.object(n, 'validate_owned'), patch.object(n, 'run', return_value=result) as mocked:
            with self.assertRaises(n.Refused): n.cleanup({'namespaces': {'od-client': 1}})
            self.assertEqual(mocked.call_count, 1)

    def test_setup_failure_rolls_back(self):
        state = []
        with patch.object(n, 'load', return_value=None), patch.object(n, 'namespaces', return_value=set()), patch.object(n, 'save'), patch.object(n, 'inode', return_value=10), patch.object(n, 'cleanup', side_effect=lambda s: state.append(dict(s['namespaces']))), patch.object(n, 'run', side_effect=[None, OSError('simulated')]):
            with self.assertRaises(OSError): n.setup()
        self.assertEqual(state, [{'od-client': 10}])

    def test_setup_failure_with_unverified_router_refuses_cleanup(self):
        with patch.object(n, 'load', return_value=None), patch.object(n, 'namespaces', return_value=set()), patch.object(n, 'save'), patch.object(n, 'inode', return_value=10), patch.object(n, 'cleanup') as cleanup, patch.object(n, 'run', side_effect=[None, None, OSError('simulated')]):
            with self.assertRaises(OSError): n.setup()
            cleanup.assert_not_called()

    def test_reject_unknown_namespace(self):
        with self.assertRaises(n.Refused): n.ns('other', n.NFT, 'flush', 'ruleset')

    def test_tampered_table_refused(self):
        with patch.object(n, 'table_digest', return_value='different'):
            with self.assertRaises(n.Refused): n.check_table({'baseline':'original'}, 'baseline')

    def test_digest_excludes_counter_values_only(self):
        def digest(packet_count, other_bytes):
            obj = {'nftables':[{'table':{'family':'inet','name':'od'}}, {'rule':{'family':'inet','table':'od','chain':'forward','expr':[{'counter':{'packets':packet_count,'bytes':10}}, {'other':{'bytes':other_bytes}}]}}]}
            result = subprocess.CompletedProcess([], 0, stdout=json.dumps(obj))
            with patch.object(n, 'ns', return_value=result): return n.table_digest()
        self.assertEqual(digest(1, 7), digest(2, 7))
        self.assertNotEqual(digest(1, 7), digest(1, 8))

    def test_intent_persisted_before_rule_write(self):
        state = {'baseline':'x', 'injected':None, 'intent':False}
        events = []
        with patch.object(n, 'verify_watchdog'), patch.object(n, 'check_table'), patch.object(n, 'tagged_handles', return_value=[]), patch.object(n, 'save', side_effect=lambda s: events.append(('save', s['intent']))), patch.object(n, 'ns', side_effect=lambda *a, **k: events.append(('nft', None))), patch.object(n, 'table_digest', side_effect=['x','y']):
            n.inject(state)
        self.assertEqual(events, [('save', True), ('nft', None), ('save', False)])

    def test_injection_refuses_unarmed_watchdog_without_mutation(self):
        state = {'baseline':'x', 'injected':None, 'intent':False}
        with patch.object(n, 'verify_watchdog', side_effect=n.Refused('timer missing')), patch.object(n, 'save') as save, patch.object(n, 'ns') as call:
            with self.assertRaises(n.Refused): n.inject(state)
        save.assert_not_called()
        call.assert_not_called()

    def test_untrusted_watchdog_source_never_arms_timer(self):
        with patch.object(n, 'secure_source', side_effect=n.Refused('untrusted source')), patch.object(n, 'run') as command, patch.object(n, 'save') as save:
            with self.assertRaises(n.Refused): n.arm_watchdog({'run_id':'a'*24})
        command.assert_not_called(); save.assert_not_called()

    def test_preflight_rejection_never_creates_namespace(self):
        with patch.object(n, 'watchdog_preflight', side_effect=n.Refused('unsafe source')), patch.object(n, 'setup') as setup:
            with self.assertRaises(n.Refused): n.start()
        setup.assert_not_called()

    def test_arm_failure_cleans_only_verified_baseline(self):
        state={'intent':False,'injected':None,'baseline':'x'}
        with patch.object(n, 'watchdog_preflight'), patch.object(n, 'setup', return_value=state), patch.object(n, 'arm_watchdog', side_effect=OSError('arm failed')), patch.object(n, 'check_table') as verified, patch.object(n, 'cleanup') as cleanup:
            with self.assertRaises(OSError): n.start()
        verified.assert_called_once_with(state, 'baseline'); cleanup.assert_called_once_with(state)

    def test_failed_intent_is_not_automatically_cleaned(self):
        state={'intent':False,'injected':None,'baseline':'x'}
        def fail_inject(s):
            s['intent']=True
            raise OSError('interrupted')
        with patch.object(n, 'watchdog_preflight'), patch.object(n, 'setup', return_value=state), patch.object(n, 'arm_watchdog'), patch.object(n, 'inject', side_effect=fail_inject), patch.object(n, 'cleanup') as cleanup:
            with self.assertRaises(OSError): n.start()
        cleanup.assert_not_called()

    def test_watchdog_requires_exact_timer_and_service_identity(self):
        rid = 'a' * 24
        timer = n.timer_name(rid)
        service = timer[:-6] + '.service'
        helper = n.helper_path(rid)
        timer_props = {'Id':timer,'LoadState':'loaded','ActiveState':'active','SubState':'waiting','Triggers':service,'Transient':'yes','FragmentPath':'/run/systemd/transient/'+timer}
        exec_start = '{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 ' + str(helper) + ' watchdog ' + rid + ' ; }'
        service_props = {'Id':service,'LoadState':'loaded','ActiveState':'inactive','Transient':'yes','FragmentPath':'/run/systemd/transient/'+service,'ExecStart':exec_start,'User':'root'}
        state = {'run_id':rid,'timer':timer,'armed_at':1000,'helper_sha256':'f'*64}
        with patch.object(n, 'helper_verified', return_value=helper), patch.object(n, 'systemd_properties', side_effect=[timer_props,service_props]), patch.object(n.time, 'monotonic_ns', return_value=1001):
            n.verify_watchdog(state)
        bad = dict(service_props, ExecStart=exec_start.replace(rid, 'b'*24))
        with patch.object(n, 'helper_verified', return_value=helper), patch.object(n, 'systemd_properties', side_effect=[timer_props,bad]), patch.object(n.time, 'monotonic_ns', return_value=1001):
            with self.assertRaises(n.Refused): n.verify_watchdog(state)

    def test_collected_transient_unit_missing_fields_is_confirmed_not_found(self):
        first=subprocess.CompletedProcess([],0,stdout='Id=gone.service\nLoadState=not-found\nActiveState=inactive\n')
        confirm=subprocess.CompletedProcess([],1,stdout='LoadState=not-found\n')
        with patch.object(n,'run',side_effect=[first,confirm]) as query:
            props=n.systemd_properties('gone.service',('Id','LoadState','ActiveState','Transient','ExecStart'))
        self.assertEqual(props['LoadState'],'not-found')
        self.assertEqual(props['ExecStart'],'')
        self.assertEqual(query.call_count,2)

    def test_missing_loaded_unit_properties_are_rejected(self):
        first=subprocess.CompletedProcess([],0,stdout='Id=foreign.service\nLoadState=loaded\n')
        confirm=subprocess.CompletedProcess([],0,stdout='LoadState=loaded\n')
        with patch.object(n,'run',side_effect=[first,confirm]):
            with self.assertRaises(n.Refused): n.systemd_properties('foreign.service',('Id','LoadState','ActiveState'))

    def test_collected_unit_replaced_during_confirmation_is_rejected(self):
        first=subprocess.CompletedProcess([],0,stdout='LoadState=not-found\n')
        confirm=subprocess.CompletedProcess([],0,stdout='LoadState=loaded\n')
        with patch.object(n,'run',side_effect=[first,confirm]):
            with self.assertRaises(n.Refused): n.systemd_properties('foreign.service',('Id','LoadState','ActiveState'))

    def test_watchdog_expiring_soon_refuses_injection(self):
        state = {'run_id':'a'*24,'timer':n.timer_name('a'*24),'armed_at':1,'helper_sha256':'f'*64}
        timer = {'Id':state['timer'],'LoadState':'loaded','ActiveState':'active','SubState':'waiting','Triggers':state['timer'][:-6]+'.service','Transient':'yes','FragmentPath':'/run/systemd/transient/'+state['timer']}
        helper=n.helper_path(state['run_id']); service=timer['Triggers']
        props={'Id':service,'LoadState':'loaded','ActiveState':'inactive','Transient':'yes','FragmentPath':'/run/systemd/transient/'+service,'ExecStart':'{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 '+str(helper)+' watchdog '+state['run_id']+' ; }','User':'root'}
        with patch.object(n, 'helper_verified', return_value=helper), patch.object(n, 'systemd_properties', side_effect=[timer,props]), patch.object(n.time, 'monotonic_ns', return_value=121_000_000_001):
            with self.assertRaises(n.Refused): n.verify_watchdog(state)

    def test_old_watchdog_cannot_touch_new_run(self):
        state={'run_id':'b'*24, 'intent':True}
        with patch.object(n, 'validate_owned') as validate, patch.object(n, 'repair') as repair, patch.object(n, 'recover_intent') as recover:
            n.watchdog_recover(state, 'a'*24, 'ignored')
            n.watchdog_recover(None, 'a'*24, 'ignored')
        validate.assert_not_called(); repair.assert_not_called(); recover.assert_not_called()

    def test_watchdog_lock_contention_closes_fd_and_refuses_recovery(self):
        from unittest.mock import Mock
        fake = Mock(LOCK_EX=1, LOCK_NB=2)
        fake.flock.side_effect = BlockingIOError('busy')
        st = Mock(st_mode=0o100600, st_uid=0, st_nlink=1)
        with patch.object(n.os, 'O_NOFOLLOW', 0, create=True), patch.object(n.os, 'open', return_value=42), patch.object(n.os, 'fstat', return_value=st), patch.object(n.os, 'close') as close:
            with self.assertRaises(BlockingIOError): n.acquire_lock(fake)
        close.assert_called_once_with(42)

    def test_watchdog_retries_contention_then_succeeds(self):
        from unittest.mock import Mock
        fake=Mock(LOCK_EX=1, LOCK_NB=2)
        fake.flock.side_effect=[BlockingIOError('busy'), None]
        st=Mock(st_mode=0o100600, st_uid=0, st_nlink=1)
        with patch.object(n.os,'O_NOFOLLOW',0,create=True), patch.object(n.os,'open',return_value=42), patch.object(n.os,'fstat',return_value=st), patch.object(n.os,'close') as close, patch.object(n.time,'monotonic',side_effect=[0,1]), patch.object(n.time,'sleep') as sleep:
            self.assertEqual(n.acquire_lock(fake, timeout=30),42)
        self.assertEqual(fake.flock.call_count,2); sleep.assert_called_once(); close.assert_not_called()

    def test_reset_stops_only_owned_inactive_watchdog(self):
        rid='a'*24; state={'run_id':rid,'timer':n.timer_name(rid),'namespaces':{},'helper_sha256':'a'*64,'armed_at':1}
        helper=n.helper_path(rid); timer={'LoadState':'loaded'}; service={'LoadState':'loaded','ActiveState':'inactive'}
        with patch.object(n.os.path,'lexists',return_value=True), patch.object(n,'helper_verified',return_value=helper), patch.object(n,'verify_units',return_value=(timer,service)), patch.object(n,'run') as command, patch.object(n,'systemd_properties',return_value={'LoadState':'not-found'}):
            self.assertEqual(n.stop_owned_watchdog(state),helper)
        command.assert_called_once_with(n.SYSTEMCTL,'stop',state['timer'],capture=True)

    def test_reset_refuses_running_or_unowned_watchdog(self):
        rid='a'*24; state={'run_id':rid,'timer':n.timer_name(rid),'namespaces':{},'helper_sha256':'a'*64,'armed_at':1}
        helper=n.helper_path(rid)
        with patch.object(n.os.path,'lexists',return_value=True), patch.object(n,'helper_verified',return_value=helper), patch.object(n,'verify_units',return_value=({'LoadState':'loaded'},{'LoadState':'loaded','ActiveState':'active'})), patch.object(n,'run') as command:
            with self.assertRaises(n.Refused): n.stop_owned_watchdog(state)
        command.assert_not_called()
        with patch.object(n.os.path,'lexists',return_value=True), patch.object(n,'helper_verified',return_value=helper), patch.object(n,'verify_units',side_effect=n.Refused('foreign unit')), patch.object(n,'run') as command:
            with self.assertRaises(n.Refused): n.stop_owned_watchdog(state)
        command.assert_not_called()

    def test_cleanup_removes_verified_snapshot_after_namespace_cleanup(self):
        from unittest.mock import Mock
        helper=Mock()
        state={'namespaces':{}, 'timer':'owned'}
        with patch.object(n,'validate_owned'), patch.object(n,'stop_owned_watchdog',return_value=helper), patch.object(n,'helper_verified') as verify, patch.object(n,'STATE') as state_file:
            n.cleanup(state)
        verify.assert_called_once_with(state); helper.unlink.assert_called_once(); state_file.unlink.assert_called_once()

    def test_unowned_watchdog_refusal_prevents_namespace_deletion(self):
        state={'namespaces':{'od-router':1}}
        empty=subprocess.CompletedProcess([],0,stdout='')
        with patch.object(n,'validate_owned'), patch.object(n,'run',return_value=empty) as run, patch.object(n,'stop_owned_watchdog',side_effect=n.Refused('unowned')):
            with self.assertRaises(n.Refused): n.cleanup(state)
        self.assertEqual(run.call_count,1)
        self.assertEqual(run.call_args.args[:3], (n.IP,'netns','pids'))

    def test_cleanup_restores_fault_before_disarming_timer(self):
        state={'namespaces':{},'injected':'recorded','timer':None}
        calls=[]
        with patch.object(n,'validate_owned'), patch.object(n,'repair',side_effect=lambda s: calls.append('repair')), patch.object(n,'stop_owned_watchdog',side_effect=lambda s: calls.append('stop')), patch.object(n,'STATE'):
            n.cleanup(state)
        self.assertEqual(calls,['repair','stop'])

    def test_watchdog_uses_intent_recovery_only_with_verified_identity(self):
        rid='a'*24
        state={'run_id':rid,'intent':True}
        path=pathlib.Path('C:/protected/watchdog.py')
        with patch.object(n, 'validate_owned') as owned, patch.object(n, 'helper_path', return_value=path), patch.object(n.os.path, 'abspath', return_value=str(path)), patch.object(n, 'helper_verified') as helper, patch.object(n, 'recover_intent') as recovery, patch.object(n, 'repair') as repair:
            n.watchdog_recover(state, rid, str(path))
        owned.assert_called_once_with(state, complete=True)
        helper.assert_called_once_with(state); recovery.assert_called_once_with(state); repair.assert_not_called()

    def test_broken_state_symlink_is_not_treated_as_absent(self):
        with patch.object(n.os.path, 'lexists', return_value=True), patch.object(n.os, 'O_NOFOLLOW', 0, create=True), patch.object(n.os, 'O_NONBLOCK', 0, create=True), patch.object(n.os, 'open', side_effect=OSError('symlink')):
            with self.assertRaises(n.Refused): n.load()

    def test_insert_failure_preserves_intent(self):
        state = {'baseline':'x', 'injected':None, 'intent':False}
        with patch.object(n, 'verify_watchdog'), patch.object(n, 'check_table'), patch.object(n, 'tagged_handles', return_value=[]), patch.object(n, 'save'), patch.object(n, 'ns', side_effect=OSError('simulated failure')):
            with self.assertRaises(OSError): n.inject(state)
        self.assertTrue(state['intent'])

    def test_recover_intent_only_removes_proven_rule(self):
        state = {'baseline':'x', 'injected':None, 'intent':True}
        with patch.object(n, 'tagged_handles', side_effect=[[8],[8]]), patch.object(n, 'table_digest', return_value='x'), patch.object(n, 'check_table'), patch.object(n, 'save'), patch.object(n, 'ns') as call:
            n.recover_intent(state)
        self.assertFalse(state['intent'])
        call.assert_called_once_with('od-router', n.NFT, 'delete', 'rule', 'inet', 'od', 'forward', 'handle', '8')

    def test_recover_intent_refuses_foreign_changes(self):
        state = {'baseline':'x', 'injected':None, 'intent':True}
        with patch.object(n, 'tagged_handles', return_value=[8]), patch.object(n, 'table_digest', return_value='foreign'), patch.object(n, 'ns') as call:
            with self.assertRaises(n.Refused): n.recover_intent(state)
        self.assertTrue(state['intent'])
        call.assert_not_called()

    def test_recover_intent_no_rule_is_repeatable_after_interruption(self):
        state = {'baseline':'x', 'injected':None, 'intent':True}
        with patch.object(n, 'tagged_handles', return_value=[]), patch.object(n, 'check_table'), patch.object(n, 'save'):
            n.recover_intent(state)
        self.assertFalse(state['intent'])

    def test_recover_intent_refuses_changed_handle(self):
        state = {'baseline':'x', 'injected':None, 'intent':True}
        with patch.object(n, 'tagged_handles', side_effect=[[8],[9]]), patch.object(n, 'table_digest', return_value='x'), patch.object(n, 'ns') as call:
            with self.assertRaises(n.Refused): n.recover_intent(state)
        call.assert_not_called()

    def test_listener_identity_mismatch_not_signalled(self):
        from unittest.mock import Mock
        proc = Mock(pid=123)
        proc.poll.return_value = None
        with patch.object(n, 'process_identity', return_value=(2,3,'/usr/bin/python3')):
            with self.assertRaises(n.Refused): n.stop_owned(proc, (1,3,'/usr/bin/python3'))
        proc.terminate.assert_not_called()
        proc.kill.assert_not_called()

    def test_fault_and_repair_probe_outcomes(self):
        from unittest.mock import Mock
        proc = Mock(pid=42)
        proc.stdout.readline.return_value = 'READY\n'
        state = {'namespaces': {'od-server': 99}}
        timeout = subprocess.CompletedProcess([], 1, stdout='', stderr='TimeoutError: timed out')
        for is_fault, http_status, expected in ((True, 28, 1), (False, 0, 0)):
            http = subprocess.CompletedProcess([], http_status, stdout='' if is_fault else 'OK', stderr='')
            with self.subTest(is_fault=is_fault), patch.object(n, 'tagged_handles', return_value=[1] if is_fault else []), patch.object(n, 'check_table'), patch.object(n.subprocess, 'Popen', return_value=proc), patch.object(n.select, 'select', return_value=([proc.stdout], [], [])), patch.object(n, 'process_identity', return_value=(7,99,'/usr/bin/python3.9')), patch.object(n, 'stop_owned') as stopped, patch.object(n, 'ns', side_effect=[None, http, timeout]):
                self.assertEqual(n.check(state), expected)
                stopped.assert_called_once()


if __name__ == '__main__':
    unittest.main()
