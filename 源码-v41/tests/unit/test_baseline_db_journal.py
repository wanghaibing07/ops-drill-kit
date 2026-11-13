import unittest
import importlib.util
from pathlib import Path
_path=Path(__file__).resolve().parents[2]/'baseline/db_journal.py'
_spec=importlib.util.spec_from_file_location('baseline_db_journal',_path)
_mod=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_mod)
reconcile=_mod.reconcile

class ReconcileTests(unittest.TestCase):
    def sample(self, **updates):
        values=dict(instance_verified=True,start=1001,end=50000,actual_count=1000,
                    actual_sha='a'*64,expected_before_sha='a'*64,expected_after_sha='b'*64)
        values.update(updates)
        return reconcile(**values)

    def test_match_requires_count_and_digest(self):
        self.assertEqual(self.sample(),'MATCHES_BEFORE_BATCH')
        self.assertEqual(self.sample(actual_count=50000,actual_sha='b'*64),'MATCHES_AFTER_BATCH')
        self.assertEqual(self.sample(actual_count=50000,actual_sha='a'*64),'NEEDS_INSPECTION')
        self.assertEqual(self.sample(actual_count=2000),'NEEDS_INSPECTION')

    def test_identity_and_invalid_inputs_fail_closed(self):
        self.assertEqual(self.sample(instance_verified=False),'IDENTITY_UNVERIFIED')
        self.assertEqual(self.sample(instance_verified=1),'IDENTITY_UNVERIFIED')
        self.assertEqual(self.sample(actual_count=True),'NEEDS_INSPECTION')
        self.assertEqual(self.sample(actual_sha='x'*64),'NEEDS_INSPECTION')
        self.assertEqual(self.sample(start=50001,end=50000),'NEEDS_INSPECTION')

if __name__=='__main__':unittest.main()
