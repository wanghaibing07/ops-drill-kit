import argparse
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

here=pathlib.Path(__file__).resolve()
source=here.with_name('opsdrill_cli.py')
if not source.exists(): source=here.parents[2]/'scripts'/'opsdrill_cli.py'
spec=importlib.util.spec_from_file_location('opsdrill_cli',source)
cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)


@unittest.skipUnless(os.geteuid()==0, 'protected state ownership tests require root')
class StateMachineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        root=pathlib.Path(self.tmp.name)
        self.patches=[patch.object(cli,'STATE_ROOT',root/'cli'),patch.object(cli,'EVENT_FILE',root/'events.jsonl'),
                      patch.object(cli,'require_root'),patch.object(cli,'script_path',return_value=root/'script'),
                      patch.object(cli,'secure_file',return_value=root/'script'),
                      patch.object(cli,'event')]
        for p in self.patches:p.start()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])

    def args(self,command,drill='L03'):
        return argparse.Namespace(command=command,drill=drill)

    def test_only_verified_identity_can_reset(self):
        rid='a'*24; unit='opsdrill-l03-'+rid+'.service'
        receipt=json.dumps({'receipt':'L03_RUN_OWNER_V1','run_id':rid,'unit':unit})
        calls=[]
        def invoke(drill, action, extra=(), capture=False):
            calls.append((action,extra))
            if action=='inject': return subprocess.CompletedProcess([],0,receipt,'')
            return 0
        with patch.object(cli,'invoke',side_effect=invoke), \
             patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            self.assertEqual(cli.action(self.args('start')),0)
            state=cli.read_state('L03');self.assertEqual(state['phase'],'ACTIVE')
            self.assertEqual(cli.action(self.args('reset')),0)
            self.assertIn(('reset',(rid,unit)),calls)
            self.assertIsNone(cli.read_state('L03'))
            self.assertEqual(cli.action(self.args('reset')),0)
            self.assertEqual(calls[-1][0],'check')

    def test_failed_start_cannot_reset_unknown_resource(self):
        def invoke(drill, action, extra=(), capture=False):
            if action=='inject': return subprocess.CompletedProcess([],1,'','')
            if action=='check': return 2
            raise AssertionError('unsafe reset called')
        with patch.object(cli,'invoke',side_effect=invoke):
            self.assertEqual(cli.action(self.args('start')),1)
            self.assertEqual(cli.read_state('L03')['phase'],'NEEDS_RESET')
            with self.assertRaisesRegex(cli.Refused,'ambiguous'):cli.action(self.args('reset'))

    def test_unintegrated_drill_cannot_start(self):
        with patch.dict(cli.REGISTRY, {'X99':'drills/example/X99'}), patch.object(cli,'invoke') as invoke:
            with self.assertRaisesRegex(cli.Refused,'not yet ownership-safe'):cli.action(self.args('start','X99'))
            invoke.assert_not_called()

    def test_check_requires_a_current_owned_attempt(self):
        for drill in ('L01','L03','N03','M01'):
            with self.subTest(drill=drill), patch.object(cli,'invoke') as invoke, \
                 patch.object(cli,'l01_clean') as l01_clean, patch.object(cli,'n03_clean') as n03_clean:
                with self.assertRaisesRegex(cli.Refused,'no active CLI-owned attempt'):
                    cli.action(self.args('check',drill))
                invoke.assert_not_called()
                l01_clean.assert_not_called()
                n03_clean.assert_not_called()

    def test_check_does_not_treat_ambiguous_attempt_as_passed(self):
        with patch.object(cli,'invoke',return_value=subprocess.CompletedProcess([],1,'','')):
            self.assertEqual(cli.action(self.args('start','N03')),1)
        with patch.object(cli,'invoke') as invoke, patch.object(cli,'n03_clean') as clean:
            with self.assertRaisesRegex(cli.Refused,'no active CLI-owned attempt'):
                cli.action(self.args('check','N03'))
            invoke.assert_not_called()
            clean.assert_not_called()

    def test_expected_run_id_is_checked_under_cli_lock(self):
        rid='a'*24; timer='opsdrill-n03-recover-'+rid+'.timer'
        receipt=json.dumps({'receipt':'N03_502_OWNER_V1','run_id':rid,'timer':timer})
        def invoke(drill, action, extra=(), capture=False):
            if action=='inject': return subprocess.CompletedProcess([],0,receipt,'')
            return 0
        with patch.object(cli,'invoke',side_effect=invoke) as call, \
             patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            self.assertEqual(cli.action(self.args('start','N03')),0)
            for action in ('check','reset'):
                args=self.args(action,'N03'); args.expect_run_id='b'*24
                before=call.call_count
                with self.assertRaisesRegex(cli.Refused,'expected run ID'):
                    cli.action(args)
                self.assertEqual(call.call_count,before)
            args=self.args('check','N03'); args.expect_run_id=rid
            self.assertEqual(cli.action(args),0)
            args=self.args('reset','N03'); args.expect_run_id=rid
            self.assertEqual(cli.action(args),0)

    def test_expected_id_allows_only_a_clean_idempotent_reset(self):
        args=self.args('reset','N03'); args.expect_run_id='a'*24
        with patch.object(cli,'n03_clean',return_value=0) as clean, patch.object(cli,'invoke') as invoke:
            self.assertEqual(cli.action(args),0)
            clean.assert_called_once()
            invoke.assert_not_called()
        with patch.object(cli,'n03_clean',return_value=2), patch.object(cli,'invoke') as invoke:
            with self.assertRaisesRegex(cli.Refused,'ambiguous'):
                cli.action(args)
            invoke.assert_not_called()

    def test_invalid_receipt_preserves_ambiguous_state(self):
        bad='{"receipt":"x","receipt":"x","run_id":"a"}'
        with patch.object(cli,'invoke',return_value=subprocess.CompletedProcess([],0,bad,'')):
            with self.assertRaises(cli.Refused):cli.action(self.args('start'))
            self.assertEqual(cli.read_state('L03')['phase'],'NEEDS_RESET')

    def test_shared_lock_blocks_concurrent_action(self):
        cli.safe_dir(); fd=cli.open_lock('controller.lock')
        try:
            with self.assertRaisesRegex(cli.Refused,'another operation'): cli.open_lock('controller.lock')
        finally: os.close(fd)

    def test_unsafe_event_symlink_blocks_injection(self):
        cli.EVENT_FILE.symlink_to('/nonexistent/opsdrill')
        with patch.object(cli,'invoke') as invoke:
            with self.assertRaises(OSError):cli.action(self.args('start'))
            invoke.assert_not_called()

    def test_ambiguous_state_reconciles_only_when_clean(self):
        with patch.object(cli,'invoke',return_value=subprocess.CompletedProcess([],1,'','')):
            self.assertEqual(cli.action(self.args('start')),1)
        with patch.object(cli,'invoke',return_value=0) as invoke:
            self.assertEqual(cli.action(self.args('reset')),0)
            self.assertEqual(invoke.call_args.args[1],'check')
            self.assertIsNone(cli.read_state('L03'))

    def test_running_is_recorded_as_pending(self):
        rid='b'*24; unit='opsdrill-l03-'+rid+'.service'
        receipt=json.dumps({'receipt':'L03_RUN_OWNER_V1','run_id':rid,'unit':unit})
        def invoke(drill, action, extra=(), capture=False):
            if action=='inject': return subprocess.CompletedProcess([],0,receipt,'')
            return subprocess.CompletedProcess([],2,'{"status":"RUNNING"}','')
        with patch.object(cli,'invoke',side_effect=invoke), \
             patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')), \
             patch.object(cli,'event') as record:
            self.assertEqual(cli.action(self.args('start')),0)
            self.assertEqual(cli.action(self.args('check')),2)
            self.assertEqual(record.call_args.args[3],'PENDING')

    def test_n02_verified_fault_is_pending_but_missing_controller_state_is_fail(self):
        cli.safe_dir()
        cli.write_state('N02',{'drill_id':'N02','phase':'ACTIVE',
                               'attempt_id':'N02-20261112-123456','run_id':'a'*24})
        for output,expected in [('N02 fault confirmed: 8080 timed out\n','PENDING'),
                                ('','FAIL')]:
            response=subprocess.CompletedProcess([],1,output,'')
            with patch.object(cli,'invoke',return_value=response),patch.object(cli,'event') as event:
                self.assertEqual(cli.action(self.args('check','N02')),1)
                self.assertEqual(event.call_args.args[3],expected)

    def test_l01_both_variants_bind_checks_and_reset_to_receipt(self):
        for variant in ('inode','deleted-open'):
            with self.subTest(variant=variant):
                rid=('c' if variant=='inode' else 'd')*24
                receipt={'receipt':'L01_INODE_OWNER_V1' if variant=='inode' else 'L01_DELETED_OWNER_V1','run_id':rid}
                expected=(variant,rid)
                if variant=='deleted-open':
                    receipt['unit']='opsdrill-l01-deleted-'+rid+'.service'
                    expected+=(receipt['unit'],)
                calls=[]
                def invoke(drill, action, extra=(), capture=False):
                    calls.append((action,extra))
                    if action=='inject': return subprocess.CompletedProcess([],0,json.dumps(receipt),'')
                    return 0
                args=self.args('start','L01');args.variant=variant
                with patch.object(cli,'invoke',side_effect=invoke), \
                     patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')):
                    self.assertEqual(cli.action(args),0)
                    self.assertEqual(cli.action(self.args('check','L01')),0)
                    self.assertEqual(cli.action(self.args('reset','L01')),0)
                    self.assertIn(('check',expected),calls)
                    self.assertIn(('reset',expected),calls)
                    self.assertIsNone(cli.read_state('L01'))

    def test_l01_wrong_receipt_never_becomes_active(self):
        rid='e'*24
        receipt={'receipt':'L01_DELETED_OWNER_V1','run_id':rid,'unit':'opsdrill-l01-deleted-'+('f'*24)+'.service'}
        args=self.args('start','L01');args.variant='deleted-open'
        with patch.object(cli,'invoke',return_value=subprocess.CompletedProcess([],0,json.dumps(receipt),'')):
            with self.assertRaisesRegex(cli.Refused,'invalid ownership'): cli.action(args)
            self.assertEqual(cli.read_state('L01')['phase'],'NEEDS_RESET')

    def test_l01_ambiguous_start_never_resets_foreign_resources(self):
        args=self.args('start','L01');args.variant='inode'
        with patch.object(cli,'invoke',return_value=subprocess.CompletedProcess([],1,'','')):
            self.assertEqual(cli.action(args),1)
        with patch.object(cli,'l01_clean',return_value=1), patch.object(cli,'invoke') as invoke:
            with self.assertRaisesRegex(cli.Refused,'ambiguous'): cli.action(self.args('reset','L01'))
            invoke.assert_not_called()

    def test_n03_binds_checks_and_reset_to_502_receipt(self):
        rid='a'*24; timer='opsdrill-n03-recover-'+rid+'.timer'
        receipt=json.dumps({'receipt':'N03_502_OWNER_V1','run_id':rid,'timer':timer})
        calls=[]
        def invoke(drill, action, extra=(), capture=False):
            calls.append((action,extra))
            if action=='inject': return subprocess.CompletedProcess([],0,receipt,'')
            return 0
        with patch.object(cli,'invoke',side_effect=invoke), \
             patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            self.assertEqual(cli.action(self.args('start','N03')),0)
            self.assertEqual(cli.read_state('N03')['timer'],timer)
            self.assertEqual(cli.action(self.args('check','N03')),0)
            self.assertEqual(cli.action(self.args('reset','N03')),0)
            self.assertIn(('inject',('--cli',)),calls)
            self.assertIn(('check',(rid,)),calls)
            self.assertIn(('reset',(rid,)),calls)

    def test_n03_mismatched_timer_never_becomes_active(self):
        rid='a'*24
        receipt=json.dumps({'receipt':'N03_502_OWNER_V1','run_id':rid,
                            'timer':'opsdrill-n03-recover-'+('b'*24)+'.timer'})
        with patch.object(cli,'invoke',return_value=subprocess.CompletedProcess([],0,receipt,'')):
            with self.assertRaisesRegex(cli.Refused,'invalid ownership'): cli.action(self.args('start','N03'))
            self.assertEqual(cli.read_state('N03')['phase'],'NEEDS_RESET')

    def test_n03_failed_start_does_not_reset_unowned_resource(self):
        with patch.object(cli,'invoke',return_value=subprocess.CompletedProcess([],1,'','')):
            self.assertEqual(cli.action(self.args('start','N03')),1)
        with patch.object(cli,'n03_clean',return_value=1), patch.object(cli,'invoke') as invoke:
            with self.assertRaisesRegex(cli.Refused,'ambiguous'): cli.action(self.args('reset','N03'))
            invoke.assert_not_called()

    def test_n03_504_uses_matching_receipt_and_run_id(self):
        rid='c'*24; timer='opsdrill-n03-recover-'+rid+'.timer'
        receipt=json.dumps({'receipt':'N03_504_OWNER_V1','run_id':rid,'timer':timer})
        calls=[]
        def invoke(drill, action, extra=(), capture=False):
            calls.append((action,extra))
            if action=='inject': return subprocess.CompletedProcess([],0,receipt,'')
            return 0
        args=self.args('start','N03');args.variant='504'
        with patch.object(cli,'invoke',side_effect=invoke), \
             patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            self.assertEqual(cli.action(args),0)
            self.assertEqual(cli.read_state('N03')['variant'],'504')
            self.assertEqual(cli.action(self.args('check','N03')),0)
            self.assertEqual(cli.action(self.args('reset','N03')),0)
            self.assertIn(('inject',('--504','--cli')),calls)
            self.assertIn(('reset',(rid,)),calls)


if __name__=='__main__': unittest.main()
