import importlib.util
import pathlib
import unittest
from unittest.mock import patch

here = pathlib.Path(__file__).resolve()
candidate = here.with_name('netcheck.py')
if not candidate.exists():
    candidate = here.parents[2] / 'scripts' / 'netcheck.py'
spec = importlib.util.spec_from_file_location('netcheck', candidate)
netcheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(netcheck)


class NetcheckTests(unittest.TestCase):
    def test_absent_namespace_does_not_execute_commands(self):
        def forbidden(_): raise AssertionError('should not execute')
        found = netcheck.build_namespace_checks('', forbidden)
        self.assertTrue(all(v['status'] == 'UNKNOWN' for v in found.values()))

    def test_only_known_namespace_is_inspected(self):
        calls = []
        found = netcheck.build_namespace_checks('od-client (id: 1)\nunknown\n',
                                               lambda args: calls.append(args) or {'status':'OK'})
        self.assertEqual(len(calls), 4)
        self.assertTrue(all('od-client' in x for x in calls))
        self.assertEqual(found['od-client']['status'], 'PRESENT')
        self.assertEqual(found['od-router']['status'], 'UNKNOWN')

    @patch.object(netcheck.subprocess, 'run', side_effect=FileNotFoundError())
    def test_missing_ip_command_is_unknown(self, _run):
        self.assertEqual(netcheck.command(['missing'])['status'], 'UNKNOWN')


if __name__=='__main__': unittest.main()
