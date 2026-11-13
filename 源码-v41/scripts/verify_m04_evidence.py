#!/usr/bin/env python3
"""Check consistency and content hashes of an existing M04 evidence bundle.

This does not replay SQL, verify live databases, or establish who ran the drill.
Run against a trusted, quiescent backup directory as an unprivileged user when
permissions permit. It never changes the bundle or performs database operations.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HASH = re.compile(r"[0-9a-f]{64}\Z")
BINLOG = re.compile(r"binlog\.(\d{6})\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    require(path.is_file() and not path.is_symlink(), "missing or unsafe " + path.name)
    require(path.stat().st_size <= 1024 * 1024, "oversized " + path.name)
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "invalid " + path.name)
    return data


def sha256_file(path):
    require(path.is_file() and not path.is_symlink(), "missing or unsafe " + path.name)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        before = __import__("os").fstat(stream.fileno())
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        after = __import__("os").fstat(stream.fileno())
    require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "file changed during hashing")
    return digest.hexdigest(), after.st_size


def position(value):
    require(isinstance(value, list) and len(value) == 2, "invalid position")
    match = BINLOG.fullmatch(value[0]) if isinstance(value[0], str) else None
    require(match is not None and type(value[1]) is int and value[1] >= 4, "invalid position")
    return int(match.group(1)), value[1]


def verify(bundle, backup):
    bundle = Path(bundle)
    manifest = read_json(bundle / "manifest.json")
    audit = read_json(bundle / "audit-result.json")
    restore = read_json(bundle / "restore-result.json")
    cleanup = read_json(bundle / "cleanup-result.json")
    for record, status in ((audit, "FORMAL_TRANSACTION_AUDIT_PASS"),
                           (restore, "FORMAL_DUAL_PITR_PASS"),
                           (cleanup, "FORMAL_CLEANUP_PASS")):
        require(record.get("status") == status, "recorded status is not PASS")
    backup_hash, _ = sha256_file(Path(backup))
    require(all(record.get("backup_sha256") == backup_hash for record in (audit, restore, cleanup)),
            "backup hash differs from records")
    files = manifest.get("files")
    require(isinstance(files, dict) and files and files == audit.get("files") == restore.get("input_sha256"),
            "binlog manifests disagree")
    names = manifest.get("input_order")
    require(isinstance(names, list) and len(names) == len(files) and len(set(names)) == len(names)
            and set(names) == set(files), "invalid binlog order")
    numbers = []
    for name in names:
        match = BINLOG.fullmatch(name) if isinstance(name, str) else None
        require(match is not None, "unsafe binlog name")
        numbers.append(int(match.group(1)))
        item = files[name]
        require(isinstance(item, dict) and set(item) == {"sha256", "size"}
                and isinstance(item["sha256"], str) and HASH.fullmatch(item["sha256"])
                and type(item["size"]) is int and item["size"] >= 4, "invalid binlog metadata")
        require(sha256_file(bundle / "input" / name) == (item["sha256"], item["size"]),
                "binlog content mismatch: " + name)
    require(numbers == list(range(numbers[0], numbers[0] + len(numbers))), "binlog sequence has a gap")
    def checked_position(value):
        parsed = position(value)
        require(value[0] in files and value[1] <= files[value[0]]["size"], "position outside input files")
        return parsed
    start, stop, delete, end = (checked_position(manifest.get(k)) for k in ("start", "stop", "first_delete_file_start", "end"))
    require(start < stop <= delete <= end, "invalid recovery position order")
    require(manifest["stop"] == audit.get("stop") == restore.get("stop") and
            manifest["first_delete_file_start"] == audit.get("first_delete_file_start") == restore.get("first_delete_file_start") and
            manifest["end"] == audit.get("end"),
            "recovery positions disagree")
    streams = audit.get("streams")
    require(isinstance(streams, list) and len(streams) == 4, "expected four audited streams")
    expected = [("orderguard", "orderguard_restore_legacy", "WRITE"),
                ("orderguard", "orderguard_restore_legacy", "UPDATE"),
                ("orderguard_stage3", "orderguard_restore_m04", "WRITE"),
                ("orderguard_stage3", "orderguard_restore_m04", "UPDATE")]
    previous = start
    hashes = []
    for index, (stream, fields) in enumerate(zip(streams, expected), 1):
        require(isinstance(stream, dict) and (stream.get("source"), stream.get("target"), stream.get("kind")) == fields,
                "unexpected replay stream")
        name = stream.get("file")
        require(isinstance(name, str) and re.fullmatch(r"%02d-[a-z0-9_-]+\.sql" % index, name), "unsafe replay name")
        stream_start, stream_end = checked_position(stream.get("start")), checked_position(stream.get("end"))
        require(previous <= stream_start < stream_end <= stop, "invalid replay stream position")
        previous = stream_end
        digest, _ = sha256_file(bundle / "replay" / name)
        require(stream.get("sha256") == digest, "replay content mismatch: " + name)
        hashes.append(digest)
    require(hashes == restore.get("streams"), "replay hash records disagree")
    require(restore.get("source_and_restore_order_sha256") == cleanup.get("source_order_sha256")
            and isinstance(cleanup.get("source_order_sha256"), dict)
            and set(cleanup["source_order_sha256"]) == {"orderguard", "orderguard_stage3"}
            and all(isinstance(x, str) and HASH.fullmatch(x) for x in cleanup["source_order_sha256"].values()),
            "source and restore order digests disagree")
    require(cleanup.get("original_logs_preserved") is True, "original logs not recorded as preserved")
    return {"status": "CONSISTENT", "binlogs_checked": len(names), "replay_streams_checked": len(streams),
            "scope": "Recorded evidence and file hashes only; no live restore, SQL semantic audit, or user practice verification."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", help="M04 evidence directory")
    parser.add_argument("backup", help="database backup referenced by the evidence")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.bundle, args.backup), ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
