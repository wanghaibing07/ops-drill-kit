import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

PARENT = Path(__file__).resolve().parent.parent
if str(PARENT) not in sys.path:
    sys.path.insert(0, str(PARENT))
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))

import mysql_backup_gate as backup
import mysql_binlog_gate as binlog
import mysql_fixture_gate as fixture
import sealed_replay
import test_pitr_audit
import vm_replay_probe as probe

DUMP = (b'-- MySQL dump 10.13\n'
        b"-- CHANGE REPLICATION SOURCE TO SOURCE_LOG_FILE='pitr-bin.000001', SOURCE_LOG_POS=123;\n"
        b'CREATE TABLE orders (id BIGINT);\n')
POS = ('pitr-bin.000001', 123)
STAMP = '2026-01-02 03:04:05'
FIRST = ('91001', '6D30342D73796E7468657469632D61', '88', '7', '1', '100', '74657374', STAMP, STAMP)
SECOND = tuple(probe.DELETED_ROW)
UPDATED = FIRST[:5] + ('101',) + FIRST[6:]


class BackupGateTests(unittest.TestCase):
    def test_matches_dump_and_quiescent_source_positions(self):
        receipt = backup.validate_dump_bytes(DUMP, POS, list(POS))
        self.assertEqual((receipt.log_name, receipt.position, receipt.length), (*POS, len(DUMP)))
        import hashlib
        self.assertEqual(receipt.sha256, hashlib.sha256(DUMP).hexdigest())

    def test_rejects_mismatched_and_invalid_positions(self):
        cases = [(POS, ('pitr-bin.000001', 124)), (POS, ('pitr-bin.000002', 123)),
                 (('../x', 123), POS), (('pitr-bin.000001', True), POS),
                 (('pitr-bin.000001', 3), POS), (('pitr-bin.000001', 124), ('pitr-bin.000001', 124))]
        for before, after in cases:
            with self.subTest(before=before, after=after), self.assertRaises(backup.BackupRejected):
                backup.validate_dump_bytes(DUMP, before, after)

    def test_rejects_missing_duplicate_malformed_late_and_oversized_coordinate(self):
        cases = [b'', DUMP.replace(b'SOURCE_LOG_POS=123', b'SOURCE_LOG_POS=124'),
                 DUMP + DUMP, DUMP + b'-- SOURCE_LOG_FILE=x\n',
                 DUMP.replace(b'-- CHANGE', b'CHANGE'),
                 b'x' * backup.MAX_HEADER + b'\n' + DUMP,
                 DUMP + b'x' * backup.MAX_DUMP]
        for data in cases:
            with self.subTest(length=len(data)), self.assertRaises(backup.BackupRejected):
                backup.validate_dump_bytes(data, POS, POS)

    def test_auditor_gates_existing_seal_helper_and_preserves_bytes(self):
        # Fake seal syscalls on Windows; real file reads and descriptor copy are
        # exercised. This does not prove Linux kernel sealing behavior.
        with tempfile.TemporaryFile(dir=Path(__file__).parent) as source, \
             tempfile.TemporaryFile(dir=Path(__file__).parent) as sink:
            source.write(DUMP)
            source.flush()
            flags = {'F_SEAL_WRITE': 8, 'F_SEAL_GROW': 4, 'F_SEAL_SHRINK': 2, 'F_SEAL_SEAL': 1,
                     'F_ADD_SEALS': 100, 'F_GET_SEALS': 101}
            with patch.multiple(sealed_replay.fcntl, create=True, **flags), \
                 patch.object(sealed_replay.fcntl, 'fcntl', create=True, return_value=15), \
                 patch.object(sealed_replay.os, 'MFD_CLOEXEC', 1, create=True), \
                 patch.object(sealed_replay.os, 'MFD_ALLOW_SEALING', 2, create=True), \
                 patch.object(sealed_replay.os, 'memfd_create', create=True, side_effect=lambda *a: os.dup(sink.fileno())):
                with backup.audited_dump_stream(source.fileno(), POS, POS) as (fd, receipt):
                    source.seek(0)
                    source.write(b'Z' * len(DUMP))
                    source.flush()
                    self.assertEqual(os.read(fd, len(DUMP)), DUMP)
                    self.assertEqual(receipt.length, len(DUMP))

    def test_rejected_coordinate_does_not_make_sealed_descriptor(self):
        with tempfile.TemporaryFile(dir=Path(__file__).parent) as source:
            source.write(DUMP)
            source.flush()
            with patch.object(sealed_replay.os, 'memfd_create', create=True) as create:
                with self.assertRaises(backup.BackupRejected):
                    with backup.audited_dump_stream(source.fileno(), POS, ('pitr-bin.000001', 124)):
                        self.fail('should not yield')
                create.assert_not_called()


class BinlogGateTests(unittest.TestCase):
    def test_exact_audited_binlog_bytes_are_copied_to_replay_descriptor(self):
        data = test_pitr_audit.example()
        with tempfile.TemporaryFile(dir=Path(__file__).parent) as source, \
             tempfile.TemporaryFile(dir=Path(__file__).parent) as sink:
            source.write(data)
            source.flush()
            flags = {'F_SEAL_WRITE': 8, 'F_SEAL_GROW': 4, 'F_SEAL_SHRINK': 2, 'F_SEAL_SEAL': 1,
                     'F_ADD_SEALS': 100, 'F_GET_SEALS': 101}
            with patch.multiple(sealed_replay.fcntl, create=True, **flags), \
                 patch.object(sealed_replay.fcntl, 'fcntl', create=True, return_value=15), \
                 patch.object(sealed_replay.os, 'MFD_CLOEXEC', 1, create=True), \
                 patch.object(sealed_replay.os, 'MFD_ALLOW_SEALING', 2, create=True), \
                 patch.object(sealed_replay.os, 'memfd_create', create=True, side_effect=lambda *a: os.dup(sink.fileno())):
                with binlog.audited_binlog_stream(source.fileno(), 4, 119, 234) as (fd, audited, receipt):
                    source.seek(0)
                    source.write(b'Z' * len(data))
                    source.flush()
                    self.assertEqual(os.read(fd, len(data)), audited)
                    self.assertEqual(audited, data)
                    self.assertEqual((receipt.start, receipt.stop, receipt.end), (4, 119, 234))
                    self.assertEqual(receipt.sha256, __import__('hashlib').sha256(data).hexdigest())

    def test_corrupt_event_or_boundary_rejected_before_seal(self):
        import pitr_audit
        data = bytearray(test_pitr_audit.example())
        data[28] ^= 1
        with tempfile.TemporaryFile(dir=Path(__file__).parent) as source:
            source.write(data)
            source.flush()
            with patch.object(sealed_replay.os, 'memfd_create', create=True) as create:
                with self.assertRaises(pitr_audit.AuditError):
                    with binlog.audited_binlog_stream(source.fileno(), 4, 119, 234):
                        self.fail('should not yield')
                create.assert_not_called()


class FixtureGateTests(unittest.TestCase):
    def test_exact_restore_and_fault(self):
        evidence = fixture.capture_fixture([SECOND, FIRST], [SECOND, UPDATED])
        fixture.verify_fault(evidence, [UPDATED])
        fixture.verify_restored(evidence, [UPDATED, SECOND])
        self.assertEqual(evidence.deleted_row, SECOND)

    def test_rejects_changed_or_missing_fields_and_extra_rows(self):
        bad_rows = [[UPDATED], [UPDATED, SECOND, FIRST], [UPDATED, SECOND[:-1] + ('other',)],
                    [UPDATED, SECOND, SECOND], [UPDATED, SECOND[:-1]], [UPDATED, list(SECOND[:-1]) + [3]]]
        for rows in bad_rows:
            with self.subTest(rows=rows), self.assertRaises(fixture.FixtureRejected):
                fixture.capture_fixture([FIRST, SECOND], rows)
        with self.assertRaises(fixture.FixtureRejected):
            fixture.capture_fixture([FIRST, SECOND[:-1] + ('other',)], [UPDATED, SECOND])

    def test_excluded_delete_and_expected_update_required(self):
        evidence = fixture.capture_fixture([FIRST, SECOND], [UPDATED, SECOND])
        for rows in ([UPDATED, SECOND], [], [FIRST]):
            with self.assertRaises(fixture.FixtureRejected):
                fixture.verify_fault(evidence, rows)
        for rows in ([UPDATED], [FIRST, SECOND], [UPDATED, SECOND, FIRST]):
            with self.assertRaises(fixture.FixtureRejected):
                fixture.verify_restored(evidence, rows)


if __name__ == '__main__':
    unittest.main()
