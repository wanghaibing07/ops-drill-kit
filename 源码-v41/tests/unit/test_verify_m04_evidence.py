import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import importlib.util

here = Path(__file__).resolve()
candidate = here.parent / 'verify_m04_evidence.py'
module_path = candidate if candidate.exists() else here.parents[2] / 'scripts' / 'verify_m04_evidence.py'
spec = importlib.util.spec_from_file_location('verify_m04_evidence', module_path)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / 'input').mkdir()
        (self.base / 'replay').mkdir()
        self.backup = self.base / 'backup.gz'
        self.backup.write_bytes(b'backup')
        self.backup_hash = hashlib.sha256(b'backup').hexdigest()
        self.files = {}
        for n in (4, 5):
            name = 'binlog.%06d' % n
            data = ('fixture%d' % n).encode() * 20
            (self.base / 'input' / name).write_bytes(data)
            self.files[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
        self.streams = []
        for i, (src, dst, kind) in enumerate([
            ('orderguard', 'orderguard_restore_legacy', 'WRITE'),
            ('orderguard', 'orderguard_restore_legacy', 'UPDATE'),
            ('orderguard_stage3', 'orderguard_restore_m04', 'WRITE'),
            ('orderguard_stage3', 'orderguard_restore_m04', 'UPDATE')], 1):
            name = '%02d-fixture.sql' % i
            data = ('stream%d' % i).encode()
            (self.base / 'replay' / name).write_bytes(data)
            self.streams.append({'source': src, 'target': dst, 'kind': kind, 'file': name,
                                 'sha256': hashlib.sha256(data).hexdigest(),
                                 'start': ['binlog.000004', 10 + i * 10],
                                 'end': ['binlog.000004', 15 + i * 10]})
        self.manifest = {'files': self.files, 'input_order': list(self.files), 'start': ['binlog.000004', 4],
                         'stop': ['binlog.000004', 60], 'first_delete_file_start': ['binlog.000005', 4],
                         'end': ['binlog.000005', 100]}
        self.audit = {'status': 'FORMAL_TRANSACTION_AUDIT_PASS', 'backup_sha256': self.backup_hash,
                      'files': self.files, 'streams': self.streams, 'stop': self.manifest['stop'],
                      'first_delete_file_start': self.manifest['first_delete_file_start'], 'end': self.manifest['end']}
        digests = {'orderguard': 'a' * 64, 'orderguard_stage3': 'b' * 64}
        self.restore = {'status': 'FORMAL_DUAL_PITR_PASS', 'backup_sha256': self.backup_hash,
                        'input_sha256': self.files, 'streams': [x['sha256'] for x in self.streams],
                        'stop': self.manifest['stop'], 'first_delete_file_start': self.manifest['first_delete_file_start'],
                        'source_and_restore_order_sha256': digests}
        self.cleanup = {'status': 'FORMAL_CLEANUP_PASS', 'backup_sha256': self.backup_hash,
                        'source_order_sha256': digests, 'original_logs_preserved': True}

    def write_records(self):
        for name, obj in [('manifest', self.manifest), ('audit-result', self.audit),
                          ('restore-result', self.restore), ('cleanup-result', self.cleanup)]:
            (self.base / (name + '.json')).write_text(json.dumps(obj), encoding='utf-8')

    def test_consistent_fixture(self):
        self.write_records()
        self.assertEqual(subject.verify(self.base, self.backup)['status'], 'CONSISTENT')

    def test_rejects_changed_input(self):
        self.write_records()
        (self.base / 'input' / 'binlog.000004').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'binlog content mismatch'):
            subject.verify(self.base, self.backup)

    def test_rejects_changed_replay(self):
        self.write_records()
        (self.base / 'replay' / self.streams[0]['file']).write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'replay content mismatch'):
            subject.verify(self.base, self.backup)

    def test_rejects_stop_after_delete(self):
        self.manifest['first_delete_file_start'] = ['binlog.000004', 50]
        self.write_records()
        with self.assertRaisesRegex(ValueError, 'position order'):
            subject.verify(self.base, self.backup)

    def test_rejects_restore_digest_drift(self):
        self.restore['source_and_restore_order_sha256'] = {'orderguard': 'a' * 64, 'orderguard_stage3': 'c' * 64}
        self.write_records()
        with self.assertRaisesRegex(ValueError, 'digests disagree'):
            subject.verify(self.base, self.backup)

    def test_rejects_path_traversal(self):
        self.streams[0]['file'] = '../foo.sql'
        self.write_records()
        with self.assertRaisesRegex(ValueError, 'unsafe replay name'):
            subject.verify(self.base, self.backup)


if __name__ == '__main__':
    unittest.main()
