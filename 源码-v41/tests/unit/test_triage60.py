import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import patch

here = pathlib.Path(__file__).resolve()
candidate = here.with_name('triage60.py')
if not candidate.exists():
    candidate = here.parents[2] / 'scripts' / 'triage60.py'
spec = importlib.util.spec_from_file_location('triage60', candidate)
triage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(triage)


class CollectTests(unittest.TestCase):
    @patch.object(triage.shutil, 'which', return_value=None)
    def test_missing_command_is_unknown(self, _which):
        result = triage.collect('missing', ['missing'])
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIsNone(result['exit_code'])

    @patch.object(triage.shutil, 'which', return_value='/bin/test')
    @patch.object(triage.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['test'], 1))
    def test_timeout_does_not_abort_triage(self, _run, _which):
        self.assertEqual(triage.collect('slow', ['test'])['reason'], 'timeout')

    @patch.object(triage.shutil, 'which', return_value='/bin/test')
    @patch.object(triage.subprocess, 'run')
    def test_nonzero_and_output_limit_are_reported(self, run, _which):
        run.return_value = subprocess.CompletedProcess(['test'], 2, b'x' * 33000, b'failure')
        result = triage.collect('bad', ['test'])
        self.assertEqual((result['status'], result['exit_code']), ('ERROR', 2))
        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['stdout']), 32768)

    @patch.object(triage.shutil, 'which', return_value='/bin/test')
    @patch.object(triage.subprocess, 'run', side_effect=PermissionError())
    def test_command_start_failure_is_unknown(self, _run, _which):
        result = triage.collect('blocked', ['test'])
        self.assertEqual((result['status'], result['reason']), ('UNKNOWN', 'PermissionError'))

    @patch.object(triage.shutil, 'which', return_value='/bin/test')
    @patch.object(triage.subprocess, 'run')
    def test_journal_and_deleted_file_content_are_not_emitted(self, run, _which):
        run.return_value = subprocess.CompletedProcess(['test'], 0, b'password=secret\n', b'token=secret')
        for name in ('journal_errors', 'deleted_open_files'):
            result = triage.collect(name, ['test'])
            self.assertNotIn('secret', str(result))
            self.assertIn('1 lines', result['stdout'])


if __name__ == '__main__':
    unittest.main()
