import argparse
import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[2]
if sys.platform!='linux': sys.modules['fcntl']=types.ModuleType('fcntl')

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

cli=load('cli_l04_candidate',HERE/'scripts'/'opsdrill_cli.py')
installer=load('l04_installer',HERE/'scripts'/'install_l04.py')


class IntegrationTest(unittest.TestCase):
    def setUp(self):
        self.rid='a'*24
        self.state=None
        self.events=[]
        self.done=set()
        self.patches=[patch.object(cli,'require_root'),patch.object(cli,'safe_dir'),
                      patch.object(cli,'open_lock',return_value=123),patch.object(cli.os,'close'),
                      patch.object(cli,'allocate_id',return_value='L04-20261113-123456'),
                      patch.object(cli,'read_state',side_effect=lambda _: self.state),
                      patch.object(cli,'write_state',side_effect=self.save),
                      patch.object(cli,'event',side_effect=lambda *x:self.events.append(x)),
                      patch.object(cli,'l04_receipt',side_effect=lambda rid:rid in self.done),
                      patch.object(cli,'l04_mark_done',side_effect=lambda rid:self.done.add(rid)),
                      patch.object(cli.os,'unlink',side_effect=lambda _: setattr(self,'state',None))]
        for p in self.patches: p.start(); self.addCleanup(p.stop)

    def save(self,drill,state): self.state=state.copy()
    def args(self,command,rid=None):
        return argparse.Namespace(command=command,drill='L04',actor='agent',expect_run_id=rid,variant=None)

    def test_bound_start_check_resolve_reset_and_repeat(self):
        receipt={'receipt':'L04_RUN_OWNER_V1','run_id':self.rid,'unit':'opsdrill-l04-'+self.rid+'-fault.service'}
        calls=[]
        def invoke(drill,action,extra=(),capture=False):
            calls.append((action,extra))
            if action=='inject': return subprocess.CompletedProcess([],0,json.dumps(receipt),'')
            if action=='check': return subprocess.CompletedProcess([],1,'{"status":"FAULT"}','')
            return 0
        with patch.object(cli,'invoke',side_effect=invoke), \
             patch.object(cli,'l04_command',return_value=['verified-owner']) as owner, \
             patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            self.assertEqual(cli.action(self.args('start')),0)
            self.assertEqual(self.state['phase'],'ACTIVE')
            owner.assert_called_with('verify-owner',(self.rid,))
            self.assertEqual(cli.action(self.args('check',self.rid)),1)
            self.assertEqual(self.events[-1][3],'PENDING')
            self.assertEqual(cli.action(self.args('resolve',self.rid)),0)
            self.assertEqual(cli.action(self.args('reset',self.rid)),0)
            self.assertIsNone(self.state)
            self.assertEqual(cli.action(self.args('reset',self.rid)),0)
            self.assertEqual(calls[-1],('reset',(self.rid,)))
            self.assertEqual([event[2] for event in self.events], ['inject','inject','check','reset'])
            self.assertTrue(all(event[2] in {'inject','diagnosis','check','hint','reset'} for event in self.events))

    def test_bad_receipt_cannot_become_active(self):
        receipt={'receipt':'L04_RUN_OWNER_V1','run_id':self.rid,'unit':'foreign.service'}
        with patch.object(cli,'invoke',return_value=subprocess.CompletedProcess([],0,json.dumps(receipt),'')):
            with self.assertRaises(cli.Refused): cli.action(self.args('start'))
            self.assertEqual(self.state['phase'],'NEEDS_RESET')

    def test_unknown_repeat_and_wrong_id_never_invoke(self):
        with patch.object(cli,'invoke') as invoke:
            with self.assertRaises(cli.Refused): cli.action(self.args('reset',self.rid))
            self.state={'drill_id':'L04','attempt_id':'L04-20261113-123456','phase':'ACTIVE','run_id':self.rid}
            with self.assertRaises(cli.Refused): cli.action(self.args('reset','b'*24))
            with self.assertRaises(cli.Refused): cli.action(self.args('resolve',None))
            invoke.assert_not_called()

    def test_failed_resolve_keeps_owned_identity_for_safe_reset(self):
        self.state={'drill_id':'L04','attempt_id':'L04-20261113-123456','phase':'ACTIVE','run_id':self.rid}
        with patch.object(cli,'invoke',return_value=2):
            self.assertEqual(cli.action(self.args('resolve',self.rid)),2)
            self.assertEqual(self.state['phase'],'NEEDS_RESET')
            self.assertEqual(self.state['run_id'],self.rid)
            self.assertEqual(self.events,[])

    def test_repeat_reset_requires_controller_to_confirm(self):
        self.done.add(self.rid)
        with patch.object(cli,'invoke',return_value=2) as invoke:
            self.assertEqual(cli.action(self.args('reset',self.rid)),2)
            invoke.assert_called_once_with('L04','reset',(self.rid,))

    def test_reset_exception_preserves_identity(self):
        self.state={'drill_id':'L04','attempt_id':'L04-20261113-123456','phase':'ACTIVE','run_id':self.rid}
        with patch.object(cli,'invoke',side_effect=OSError('failed')):
            with self.assertRaises(OSError): cli.action(self.args('reset',self.rid))
            self.assertEqual(self.state['phase'],'NEEDS_RESET')
            self.assertEqual(self.state['run_id'],self.rid)

    def test_owner_verification_failure_preserves_unowned_state(self):
        receipt={'receipt':'L04_RUN_OWNER_V1','run_id':self.rid,'unit':'opsdrill-l04-'+self.rid+'-fault.service'}
        with patch.object(cli,'invoke',return_value=subprocess.CompletedProcess([],0,json.dumps(receipt),'')), \
             patch.object(cli,'l04_command',return_value=['owner']), \
             patch.object(cli.subprocess,'run',return_value=subprocess.CompletedProcess([],2,'','')):
            with self.assertRaises(cli.Refused): cli.action(self.args('start'))
            self.assertEqual(self.state['phase'],'NEEDS_RESET')
            self.assertNotIn('run_id',self.state)

    def test_pinned_modules_match_installer_and_cli(self):
        self.assertEqual(installer.MANIFEST,cli.L04_MANIFEST)
        for name,digest in cli.L04_MANIFEST.items():
            self.assertEqual(hashlib.sha256((HERE/'drills'/'linux'/'L04'/name).read_bytes()).hexdigest(),digest)

    def test_installer_rejects_tampered_source(self):
        flags={name:getattr(installer.os,name,0) for name in ('O_NOFOLLOW','O_NONBLOCK','O_CLOEXEC')}
        controller=(HERE/'drills'/'linux'/'L04'/'controller.py').read_bytes()
        with patch.multiple(installer.os,create=True,**flags), patch.object(installer.os,'open',return_value=123), \
             patch.object(installer,'read_file',side_effect=[controller,b'tampered']):
            with self.assertRaises(installer.Refused): installer.source_files('unused')


if __name__=='__main__': unittest.main()
