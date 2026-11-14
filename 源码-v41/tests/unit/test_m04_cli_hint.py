import importlib.util
import hashlib
import io
from pathlib import Path
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('m04_cli_hint',ROOT/'scripts/opsdrill_cli.py')
cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)

class M04HintTests(unittest.TestCase):
    def test_manifest_matches_project_sources(self):
        base=ROOT/'experimental/m04'
        for name,digest in cli.M04_MANIFEST.items():
            self.assertEqual(hashlib.sha256((base/name).read_bytes()).hexdigest(),digest,name)

    def test_m04_dispatch_uses_sixteen_character_id(self):
        rid='a'*16
        args=SimpleNamespace(drill='M04',command='check',expect_run_id=rid,n04_version=None)
        state={'phase':'ACTIVE','run_id':rid}
        with patch.object(cli,'require_root'),patch.object(cli,'safe_dir'),patch.object(cli,'open_lock',return_value=42), \
             patch.object(cli.os,'close'),patch.object(cli,'read_state',return_value=state),patch.object(cli,'m04_action',return_value=5):
            self.assertEqual(cli.action(args),5)
            args.expect_run_id='b'*24
            with self.assertRaises(cli.Refused):cli.action(args)

    def test_hint_and_note_record_events(self):
        state={'phase':'ACTIVE','attempt_id':'M04-20261113-123456','run_id':'a'*16,'m04_version':'synthetic-v3'}
        hint=MagicMock();hint.stat.return_value.st_size=5;hint.read_text.return_value='hint'
        with patch.object(cli,'secure_file',return_value=hint),patch.object(cli,'event') as event,redirect_stdout(io.StringIO()):
            self.assertEqual(cli.m04_action(SimpleNamespace(command='hint'),state,None),0)
            self.assertEqual(cli.m04_action(SimpleNamespace(command='note'),state,None),0)
        self.assertEqual([call.args[2] for call in event.call_args_list],['hint','diagnosis'])
        self.assertTrue(all(call.args[5]['run_id']=='a'*16 and call.args[5]['m04_version']=='synthetic-v3' for call in event.call_args_list))

    def test_no_active_attempt_refuses(self):
        for command in ('hint','note'):
            with self.assertRaises(cli.Refused):cli.m04_action(SimpleNamespace(command=command),None,None)

if __name__=='__main__':unittest.main()
