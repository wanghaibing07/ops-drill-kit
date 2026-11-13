import importlib.util
import pathlib
import stat
import sys
import types
import unittest
from unittest import mock

# The tests are intentionally offline and also run on Windows.
sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
spec = importlib.util.spec_from_file_location('n01', pathlib.Path(__file__).with_name('n01.py'))
n01 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n01)


class ProcessGuardTests(unittest.TestCase):
    def child(self):
        obj = object.__new__(n01.BoundedChild)
        obj.proc = mock.Mock(pid=111)
        obj.proc.poll.return_value = None
        obj.parent = [10, 50, '/usr/bin/timeout']
        obj.child = (112, [11, 50, '/usr/sbin/dnsmasq'])
        return obj

    def test_changed_child_is_not_signalled(self):
        obj = self.child()
        with mock.patch.object(n01, 'identity', side_effect=[[10,50,'/usr/bin/timeout'], [12,50,'/usr/sbin/dnsmasq']]), \
             mock.patch.object(n01, 'child_ids', return_value=[112]), \
             mock.patch.object(n01.signal, 'pidfd_send_signal', create=True) as send:
            with self.assertRaises(n01.Refused): obj.stop()
            send.assert_not_called()

    def test_changed_parent_is_refused(self):
        obj = self.child()
        with mock.patch.object(n01, 'identity', return_value=[99,50,'/usr/bin/timeout']):
            with self.assertRaises(n01.Refused): obj.verify()

    def test_wrong_namespace_is_refused(self):
        obj = self.child()
        with mock.patch.object(n01, 'identity', side_effect=[[10,50,'/usr/bin/timeout'], [11,51,'/usr/sbin/dnsmasq']]), \
             mock.patch.object(n01, 'child_ids', return_value=[112]):
            with self.assertRaises(n01.Refused): obj.verify()

    def test_extra_child_is_refused(self):
        obj = self.child()
        with mock.patch.object(n01, 'identity', return_value=obj.parent), \
             mock.patch.object(n01, 'child_ids', return_value=[112,113]):
            with self.assertRaises(n01.Refused): obj.verify()


class ProbeTests(unittest.TestCase):
    def test_private_mount_and_fixed_namespace(self):
        with mock.patch.object(n01.subprocess, 'run') as run:
            n01.probe('od-client', pathlib.Path('/run/opsdrill-n01/resolv.conf'), ['/usr/bin/getent','ahostsv4','app.lab'])
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[:5], ['/usr/sbin/ip','netns','exec','od-client','/usr/bin/unshare'])
        self.assertIn('--mount', cmd)
        self.assertIn('mount --make-rprivate /', cmd[8])
        self.assertNotIn('shell', run.call_args.kwargs)

    def test_fault_repair_and_other_failures(self):
        def result(code, output=''): return types.SimpleNamespace(returncode=code, stdout=output)
        ok = result(0)
        wrong_hosts = result(0, '10.203.2.99 STREAM app.lab\n')
        good_hosts = result(0, '10.203.2.2 STREAM app.lab\n')
        wrong_dns = result(0, '10.203.2.99\n')
        good_dns = result(0, '10.203.2.2\n')
        self.assertEqual(n01.judge(ok, wrong_hosts, wrong_dns, result(7))[0], 1)
        self.assertEqual(n01.judge(ok, good_hosts, good_dns, ok)[0], 0)
        self.assertEqual(n01.judge(result(7), wrong_hosts, wrong_dns, result(7))[0], 2)
        self.assertEqual(n01.judge(ok, good_hosts, result(9), ok)[0], 2)
        self.assertEqual(n01.judge(ok, good_hosts, good_dns, result(7))[0], 2)


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.rid = 'a' * 24
        self.other = 'b' * 24
        self.meta = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1, st_size=80)
        self.data = ('{"version":1,"run_id":"' + self.rid + '","result":"clean"}').encode()

    def test_only_matching_run_is_accepted(self):
        n01.validate_completion(self.meta, self.data, self.rid)
        with self.assertRaises(n01.Refused): n01.validate_completion(self.meta, self.data, self.other)

    def test_unsafe_or_corrupt_receipt_is_refused(self):
        for changes, data in (({'st_uid': 1}, self.data), ({'st_nlink': 2}, self.data),
                              ({'st_mode': stat.S_IFREG | 0o644}, self.data),
                              ({}, b'{'), ({}, b'{"version":1,"version":1}')):
            values = vars(self.meta) | changes
            with self.assertRaises(n01.Refused): n01.validate_completion(types.SimpleNamespace(**values), data, self.rid)

    def test_invalid_filename_is_rejected(self):
        for value in ('../a', '', 'A' * 24):
            with self.assertRaises(n01.Refused): n01.completion_path(value)

    def test_repeat_needs_receipt_and_rechecks_active_resources(self):
        topology = mock.Mock()
        topology.ROOT.lstat.return_value = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        topology.acquire_lock.return_value = 100
        topology.NAMES = ('od-client', 'od-router', 'od-server')
        topology.load.return_value = None
        topology.namespaces.return_value = set()
        with mock.patch.object(n01.os.path, 'lexists', return_value=False), \
             mock.patch.object(n01.os, 'close'), \
             mock.patch.object(n01, 'verify_completion', side_effect=[None, FileNotFoundError]):
            self.assertEqual(n01.reset_completed(topology, self.rid), 0)
            with self.assertRaises(FileNotFoundError): n01.reset_completed(topology, self.other)
        with mock.patch.object(n01.os.path, 'lexists', side_effect=[False, False, True]), \
             mock.patch.object(n01.os, 'close'), mock.patch.object(n01, 'verify_completion') as verify:
            with self.assertRaises(n01.Refused): n01.reset_completed(topology, self.rid)
            verify.assert_not_called()


if __name__ == '__main__': unittest.main()
