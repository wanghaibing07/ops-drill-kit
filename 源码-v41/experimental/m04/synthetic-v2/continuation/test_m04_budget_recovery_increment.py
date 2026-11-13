"""Focused local simulations; no VM, systemd or MySQL is contacted."""
from copy import deepcopy
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))

import mysql_lifecycle_candidate as lifecycle
import mysql_synthetic_drill as drill
from test_mysql_lifecycle_candidate import LifecycleTests, RID


class InterruptedStopTests(unittest.TestCase):
    def setUp(self):
        baseline = LifecycleTests()
        baseline.setUp()
        self.state = deepcopy(baseline.state)
        self.state['candidate_phase'] = 'RESETTING'
        self.state['candidate_stopping'] = 'target'

    def properties(self, name):
        if name.endswith('-init.service'):
            return {'LoadState': 'not-found', 'ActiveState': 'inactive'}
        return {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0'}

    def test_recognizes_interrupted_stop_and_stops_only_remaining_instance(self):
        stops, saves = [], []
        expected = self.state['candidate_identities']['target']['invocation_id']
        with patch.object(lifecycle.ctl, 'properties', side_effect=self.properties), \
             patch.object(lifecycle.ctl, 'run', return_value='InvocationID=' + expected), \
             patch.object(lifecycle.os.path, 'lexists', return_value=False), \
             patch.object(lifecycle.ctl, 'verify'), \
             patch.object(lifecycle.ctl, 'stop_one', side_effect=lambda rid, label: stops.append(label)), \
             patch.object(lifecycle.ctl, 'save', side_effect=lambda d, s: saves.append(deepcopy(s))):
            lifecycle.reset_bound(RID, self.state, Path('.'))
        self.assertEqual(stops, ['source'])
        self.assertTrue(any(s.get('candidate_stopped') == ['target'] and 'candidate_stopping' not in s for s in saves))
        self.assertTrue(any(s.get('candidate_stopping') == 'source' for s in saves))
        self.assertEqual(self.state['candidate_phase'], 'STOPPED')

    def test_unknown_or_replaced_unit_never_stops_other_instance(self):
        cases = [({'LoadState': 'not-found', 'ActiveState': 'inactive'}, 'same', False),
                 ({'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0'}, 'different', False),
                 ({'LoadState': 'loaded', 'ActiveState': 'failed', 'MainPID': '4'}, 'same', False),
                 ({'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0'}, 'same', True)]
        expected = self.state['candidate_identities']['target']['invocation_id']
        for props, identity, socket in cases:
            state = deepcopy(self.state)
            def properties(name):
                return {'LoadState': 'not-found', 'ActiveState': 'inactive'} if name.endswith('-init.service') else props
            with self.subTest(props=props, identity=identity, socket=socket), \
                 patch.object(lifecycle.ctl, 'properties', side_effect=properties), \
                 patch.object(lifecycle.ctl, 'run', return_value='InvocationID=' + (expected if identity == 'same' else 'f'*32)), \
                 patch.object(lifecycle.os.path, 'lexists', return_value=socket), \
                 patch.object(lifecycle.ctl, 'verify'), patch.object(lifecycle.ctl, 'save'), \
                 patch.object(lifecycle.ctl, 'stop_one') as stop:
                with self.assertRaises(lifecycle.ctl.SafetyError):
                    lifecycle.reset_bound(RID, state, Path('.'))
                stop.assert_not_called()
                self.assertNotIn('candidate_stopped', state)

    def test_stop_failure_keeps_durable_intent_and_retry_checks_identity(self):
        state = deepcopy(self.state)
        state.pop('candidate_stopping')
        saves = []
        with patch.object(lifecycle.ctl, 'properties', return_value={'LoadState': 'not-found', 'ActiveState': 'inactive'}), \
             patch.object(lifecycle.ctl, 'verify'), \
             patch.object(lifecycle.ctl, 'save', side_effect=lambda d, s: saves.append(deepcopy(s))), \
             patch.object(lifecycle.ctl, 'stop_one', side_effect=RuntimeError('interrupted')):
            with self.assertRaises(RuntimeError):
                lifecycle.reset_bound(RID, state, Path('.'))
        self.assertEqual(saves[-1]['candidate_stopping'], 'target')
        self.assertNotIn('candidate_stopped', saves[-1])

    def test_active_pending_instance_must_be_verified_then_stopped(self):
        stops = []
        def properties(name):
            if name.endswith('-init.service'):
                return {'LoadState': 'not-found', 'ActiveState': 'inactive'}
            return {'LoadState': 'loaded', 'ActiveState': 'active'}
        with patch.object(lifecycle.ctl, 'properties', side_effect=properties), \
             patch.object(lifecycle.ctl, 'verify') as verify, \
             patch.object(lifecycle.ctl, 'save'), \
             patch.object(lifecycle.ctl, 'stop_one', side_effect=lambda rid, label: stops.append(label)):
            lifecycle.reset_bound(RID, self.state, Path('.'))
        self.assertEqual(stops, ['target', 'source'])
        self.assertGreaterEqual(verify.call_count, 5)

    def test_malformed_intent_rejected_before_stop(self):
        self.state['candidate_stopping'] = 'source'
        with patch.object(lifecycle.ctl, 'stop_one') as stop:
            with self.assertRaises(lifecycle.ctl.SafetyError):
                lifecycle.reset_bound(RID, self.state, Path('.'))
            stop.assert_not_called()


class OutputBudgetTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'requires Linux RLIMIT_FSIZE')
    def test_real_child_cannot_grow_file_past_limit(self):
        from functools import partial
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'out'
            with output.open('wb') as out:
                result = subprocess.run([sys.executable, '-c', 'import os; data=b"x"*4096; pos=0\nwhile pos<len(data): pos+=os.write(1,data[pos:])'],
                                        stdout=out, stderr=subprocess.DEVNULL,
                                        preexec_fn=partial(drill.cap_output, 1024), check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertLessEqual(output.stat().st_size, 1024)

    def test_output_cap_sets_soft_and_hard_limit(self):
        calls = []
        resource = types.SimpleNamespace(RLIMIT_FSIZE=1, setrlimit=lambda *a: calls.append(a))
        with patch.dict(sys.modules, {'resource': resource}):
            drill.cap_output(6)
        self.assertEqual(calls, [(1, (6, 6))])

    def test_remaining_uses_existing_dump_and_rejects_exhaustion(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(drill.os, 'O_NOFOLLOW', getattr(drill.os, 'O_NOFOLLOW', 0), create=True), \
             patch.object(drill.backup_gate, 'MAX_DUMP', 10):
            directory = Path(tmp)
            dump = directory / 'synthetic-full.sql'
            dump.write_bytes(b'1234')
            self.assertEqual(drill.remaining_replay_bytes(directory), 6)
            dump.write_bytes(b'1234567890')
            with self.assertRaises(drill.ctl.SafetyError):
                drill.remaining_replay_bytes(directory)

    def test_replay_child_receives_only_remaining_budget(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(drill.os, 'O_NOFOLLOW', getattr(drill.os, 'O_NOFOLLOW', 0), create=True), \
             patch.object(drill.backup_gate, 'MAX_DUMP', 10), \
             patch.object(drill.ctl, 'verify'), patch.object(drill.os, 'lseek'), \
             patch.object(drill.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0)) as run:
            directory = Path(tmp)
            (directory / 'synthetic-full.sql').write_bytes(b'1234')
            drill.generate_replay('0123456789abcdef', {'primary_uuid': 'p', 'uuids': {'source': 's'}}, directory, 1, 4, 5)
            self.assertEqual(run.call_args.kwargs['preexec_fn'].args, (6,))
            self.assertEqual(run.call_args.kwargs['preexec_fn'].func, drill.cap_output)

    def test_invalid_dump_is_rejected_before_spawning_child(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(drill.os, 'O_NOFOLLOW', getattr(drill.os, 'O_NOFOLLOW', 0), create=True), \
             patch.object(drill.os, 'fstat', return_value=types.SimpleNamespace(st_mode=0, st_nlink=1, st_size=1)), \
             patch.object(drill.ctl, 'verify'), patch.object(drill.subprocess, 'run') as run:
            directory = Path(tmp)
            (directory / 'synthetic-full.sql').write_bytes(b'x')
            with self.assertRaises(drill.ctl.SafetyError):
                drill.generate_replay('0123456789abcdef', {'primary_uuid': 'p', 'uuids': {'source': 's'}}, directory, 1, 4, 5)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
