import importlib.util
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, 'scripts')
spec = importlib.util.spec_from_file_location('m02_retry_controller', 'scripts/m02_retry_controller.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RecoveryTests(unittest.TestCase):
    def test_transient_transaction_requires_two_clean_samples(self):
        base = {'statuses': m.BASELINE, 'active_transactions': 0, 'active_waits': 0}
        pending = dict(base, active_transactions=1)
        with patch.object(m, 'take_snapshot', side_effect=[pending, base, base]), patch.object(m.time, 'sleep'):
            ok, samples = m.wait_for_clean_snapshot()
        self.assertTrue(ok)
        self.assertEqual([x['active_transactions'] for x in samples], [1, 0, 0])

    def test_persistent_wait_does_not_pass(self):
        sample = {'statuses': m.BASELINE, 'active_transactions': 0, 'active_waits': 1}
        with patch.object(m, 'take_snapshot', return_value=sample), patch.object(m.time, 'sleep'):
            ok, samples = m.wait_for_clean_snapshot(timeout=0)
        self.assertFalse(ok)
        self.assertEqual(samples[-1]['active_waits'], 1)


if __name__ == '__main__': unittest.main()
