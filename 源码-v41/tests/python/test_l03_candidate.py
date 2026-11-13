import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock

# fcntl is Linux-only; no locking or actual I/O is exercised on Windows.
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
MODULE = pathlib.Path(__file__).resolve().parents[2] / 'drills/linux/L03/l03_control.py'
spec = importlib.util.spec_from_file_location('l03_candidate', MODULE)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class MetricsTest(unittest.TestCase):
    def test_cpu_excludes_guest_to_avoid_double_count(self):
        self.assertEqual(c.cpu_counters('cpu  10 20 30 40 50 60 70 80 90 100\n'), (360, 50))

    def test_bad_cpu_stat_fails_closed(self):
        for data in ('cpu0 1 2 3 4 5', 'cpu 1 2', 'cpu 1 2 x 4 5'):
            with self.subTest(data=data), self.assertRaises((c.Unsafe, ValueError)):
                c.cpu_counters(data)

    def check(self, cpu=(200, 30), read=64*c.MIB, elapsed=2_000_000_000, status='COMPLETED', health=True):
        return c.observation((100, 10), cpu, 0, read, elapsed, status, health)

    def test_positive_is_system_observation_not_attribution(self):
        x = self.check()
        self.assertEqual(x['verdict'], 'SYSTEM_IOWAIT_OBSERVED')
        self.assertEqual(x['iowait_percent'], 20)
        self.assertIn('REQUIRES', x['reason'])

    def test_insufficient_or_bad_inputs_are_inconclusive(self):
        scenarios = [
            (dict(cpu=(200, 9)), 'COUNTER_INVALID'),
            (dict(cpu=(100, 10)), 'COUNTER_INVALID'),
            (dict(read=-1), 'COUNTER_INVALID'),
            (dict(read=64*c.MIB-1), 'STORAGE_READ_TOO_LOW'),
            (dict(elapsed=1_999_999_999), 'WINDOW_TOO_SHORT'),
            (dict(status='FAILED'), 'WORKLOAD_OR_HEALTH_FAILED'),
            (dict(health=False), 'WORKLOAD_OR_HEALTH_FAILED'),
        ]
        for args, reason in scenarios:
            with self.subTest(args=args):
                x = self.check(**args)
                self.assertEqual((x['verdict'], x['reason']), ('INCONCLUSIVE', reason))
        self.assertEqual(c.observation(None, (1, 1), 0, 1, 3, 'COMPLETED', True)['reason'], 'METRICS_UNAVAILABLE')

    def test_threshold_uses_unrounded_value(self):
        x = c.observation((0, 0), (10001, 1000), 0, 64*c.MIB, 2_000_000_000, 'COMPLETED', True)
        self.assertEqual(x['iowait_percent'], 10.0)
        self.assertEqual(x['verdict'], 'IOWAIT_THRESHOLD_NOT_MET')


class WritePayloadTest(unittest.TestCase):
    def test_bounded_nonzero_distinct_blocks_and_partial_writes(self):
        chunks = []
        def write(_fd, view):
            chunks.append(bytes(view[:16]))
            return min(len(view), 128*1024)
        with mock.patch.object(c, 'WRITE_MIB', 1), mock.patch.object(c.os, 'write', side_effect=write):
            total = sum(c.write_payload(1, lambda: None, lambda: None))
        self.assertEqual(total, c.MIB)
        self.assertEqual(len(chunks), 8)
        self.assertNotEqual(chunks[0], b'\0'*16)
        self.assertEqual(len(set(chunks)), len(chunks))

    def test_write_stops_on_health_deadline_and_zero_write(self):
        def fail():
            raise c.Unsafe('stop')
        for which in ('health', 'deadline', 'write'):
            with self.subTest(which=which), mock.patch.object(c.os, 'write', return_value=0) as write:
                with self.assertRaises(c.Unsafe):
                    list(c.write_payload(1, fail if which == 'deadline' else lambda: None,
                                         fail if which == 'health' else lambda: None))
                self.assertEqual(write.call_count, 1 if which == 'write' else 0)


class DirectReadTest(unittest.TestCase):
    def test_four_pass_budget_and_periodic_health(self):
        deadlines, checks = [], []
        with mock.patch.object(c.os, 'lseek', return_value=0), \
             mock.patch.object(c.os, 'readv', return_value=c.READ_CHUNK, create=True) as read:
            total = sum(sum(c.direct_read_pass(8, bytearray(c.READ_CHUNK),
                        lambda: deadlines.append(1), lambda: checks.append(1))) for _ in range(c.READ_PASSES))
        self.assertEqual(total, 256*c.MIB)
        self.assertEqual(read.call_count, 256)
        self.assertEqual(len(deadlines), 256)
        self.assertEqual(len(checks), 64)

    def test_short_read_never_counts_as_success(self):
        with mock.patch.object(c.os, 'lseek'), mock.patch.object(c.os, 'readv', return_value=0, create=True):
            with self.assertRaisesRegex(c.Unsafe, 'DIRECT_READ_SHORT'):
                list(c.direct_read_pass(1, bytearray(c.READ_CHUNK), lambda: None, lambda: None))

    def test_partial_read_is_accounted_before_failure(self):
        with mock.patch.object(c.os, 'lseek'), mock.patch.object(c.os, 'readv', return_value=4096, create=True):
            stream = c.direct_read_pass(1, bytearray(c.READ_CHUNK), lambda: None, lambda: None)
            self.assertEqual(next(stream), 4096)
            with self.assertRaisesRegex(c.Unsafe, 'DIRECT_READ_SHORT'):
                next(stream)

    def test_health_failure_and_deadline_stop_before_read(self):
        for which in ('health', 'deadline'):
            def fail():
                raise c.Unsafe(which)
            with self.subTest(which=which), mock.patch.object(c.os, 'lseek'), \
                 mock.patch.object(c.os, 'readv', create=True) as read:
                with self.assertRaisesRegex(c.Unsafe, which):
                    list(c.direct_read_pass(1, bytearray(c.READ_CHUNK),
                         fail if which == 'deadline' else lambda: None,
                         fail if which == 'health' else lambda: None))
                read.assert_not_called()

    def test_os_failure_propagates_instead_of_buffered_retry(self):
        with mock.patch.object(c.os, 'lseek'), \
             mock.patch.object(c.os, 'readv', side_effect=OSError('unsupported'), create=True) as read:
            with self.assertRaises(OSError):
                list(c.direct_read_pass(1, bytearray(c.READ_CHUNK), lambda: None, lambda: None))
            self.assertEqual(read.call_count, 1)


if __name__ == '__main__':
    unittest.main()
