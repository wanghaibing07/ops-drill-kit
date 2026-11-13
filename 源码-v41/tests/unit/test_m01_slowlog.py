import hashlib
import importlib
import json
import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import m01_slowlog


class SlowLogParserTests(unittest.TestCase):
    def test_only_target_metrics_are_returned(self):
        marker = "M01_SLOWLOG_test123"
        log = (
            b"# Time: 2026-11-10T01:00:00.000000Z\n"
            b"# User@Host: other[other] @ localhost []\n"
            b"# Query_time: 0.100000 Lock_time: 0.000001 Rows_sent: 1 Rows_examined: 9\n"
            b"SELECT 'OTHER_SESSION_SECRET';\n"
            b"# Time: 2026-11-10T01:00:01.000000Z\n"
            b"# User@Host: stage3_reader[stage3_reader] @ localhost []\n"
            b"# Query_time: 0.001200 Lock_time: 0.000001 Rows_sent: 20 Rows_examined: 20\n"
            + ("SELECT /* " + marker + " */ id FROM orders;\n").encode()
        )
        count, metrics = m01_slowlog.parse_target_metrics(log, marker)
        self.assertEqual(count, 1)
        self.assertEqual(metrics["rows_sent"], 20)
        self.assertEqual(metrics["rows_examined"], 20)
        self.assertNotIn("OTHER_SESSION_SECRET", json.dumps(metrics))

    def test_duplicate_marker_is_rejected(self):
        marker = "M01_SLOWLOG_dup"
        entry = (
            b"# Time: t\n"
            b"# Query_time: 0.001 Lock_time: 0 Rows_sent: 20 Rows_examined: 20\n"
            + ("SELECT /* " + marker + " */ 1;\n").encode()
        )
        count, metrics = m01_slowlog.parse_target_metrics(entry + entry, marker)
        self.assertEqual(count, 2)
        self.assertIsNone(metrics)


class DigestContractTests(unittest.TestCase):
    def test_imports_existing_benchmark_digest_as_single_source(self):
        digest = m01_slowlog.load_existing_result_digest()
        rows = [
            (2, "OG000000000002", 2500, datetime(2026, 1, 2, 3, 4, 5)),
            (1, "OG000000000001", 1000, datetime(2026, 1, 1, 3, 4, 5)),
        ]
        canonical = sorted(
            (int(row[0]), str(row[1]), int(row[2]), str(row[3]))
            for row in rows
        )
        expected = hashlib.sha256(
            json.dumps(
                canonical,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        self.assertEqual(digest(rows), expected)


if __name__ == "__main__":
    unittest.main()
