#!/usr/bin/env python3
"""M01: exactly one controlled index-visibility fault; no global setting writes."""
import argparse
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "lib" / "guard.sh"
ADMIN = "/etc/opsdrill/mysql-admin.cnf"
BASE = Path("/var/lib/opsdrill/m01")
LOCK = BASE / "m01.lock"
STATE = BASE / "state.json"
INDEX = "idx_merchant_status_created"
SQL = ("SELECT id, order_no, amount_cents, created_at FROM orders "
       "WHERE merchant_id=88 AND order_status=1 "
       "AND created_at >= '2026-10-01 00:00:00' "
       "ORDER BY created_at DESC LIMIT 20")
WATCH = ("slow_query_log", "long_query_time", "log_output",
         "log_queries_not_using_indexes", "local_infile")

class Error(Exception):
    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


def safety():
    if os.geteuid() != 0:
        raise Error("requires sudo/root", 3)
    marker = Path('/etc/opsdrill-lab')
    try:
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                    or st.st_mode & 0o022 or st.st_size > 64
                    or os.read(fd, 65).strip() != b'ops-drill-kit'):
                raise Error("unsafe lab marker", 3)
        finally:
            os.close(fd)
    except OSError as exc:
        raise Error("lab marker inaccessible", 3) from exc
    virt = subprocess.run(['/usr/bin/systemd-detect-virt','--vm'], capture_output=True, text=True, timeout=10)
    if virt.returncode or virt.stdout.strip() != 'vmware':
        raise Error("requires VMware VM", 3)
    for parent in Path(ADMIN).parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Error("unsafe MySQL configuration parent", 3)
    fd = os.open(ADMIN, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
            raise Error("unsafe MySQL admin configuration", 3)
    finally:
        os.close(fd)


def db(sql):
    p = subprocess.run(["/usr/bin/mysql", f"--defaults-extra-file={ADMIN}",
                        "--batch", "--skip-column-names", "--raw", "--silent",
                        "-D", "orderguard_stage3"], input=sql,
                       text=True, capture_output=True, timeout=30, env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C", "LANG":"C"})
    if p.returncode:
        # Avoid propagating any potential secret from SQL client diagnostic text.
        raise Error("MySQL command failed (exit code %d)" % p.returncode)
    return p.stdout.strip()


def require_dir():
    if BASE.is_symlink():
        raise Error("M01 state directory is a symlink", 3)
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = BASE.lstat()
    if (not stat.S_ISDIR(s.st_mode) or s.st_uid != 0
            or stat.S_IMODE(s.st_mode) != 0o700):
        raise Error("M01 state dir must be root-owned 0700", 3)


def acquire_lock():
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(LOCK, flags, 0o600)
    s = os.fstat(fd)
    if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0
            or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1):
        os.close(fd)
        raise Error("unsafe M01 lock file", 3)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Error("another M01 operation holds lock", 3)
    return fd


def index_rows():
    out = db("SELECT SEQ_IN_INDEX, COLUMN_NAME, IS_VISIBLE "
             "FROM information_schema.statistics "
             "WHERE TABLE_SCHEMA='orderguard_stage3' AND TABLE_NAME='orders' "
             "AND INDEX_NAME='idx_merchant_status_created' "
             "ORDER BY SEQ_IN_INDEX;")
    rows = [x.split("\t") for x in out.splitlines() if x]
    if len(rows) != 3:
        raise Error("target index missing or unexpected columns")
    expected = ["merchant_id", "order_status", "created_at"]
    for n, (row, name) in enumerate(zip(rows, expected), 1):
        if row[:2] != [str(n), name] or row[2] not in ("YES", "NO"):
            raise Error("target index definition differs from baseline")
    values = {row[2] for row in rows}
    if len(values) != 1:
        raise Error("inconsistent index visibility")
    return values.pop()


def globals_read():
    out = db("SELECT @@GLOBAL.slow_query_log, @@GLOBAL.long_query_time, "
             "@@GLOBAL.log_output, @@GLOBAL.log_queries_not_using_indexes, "
             "@@GLOBAL.local_infile;")
    parts = out.split("\t")
    if len(parts) != len(WATCH):
        raise Error("unexpected global settings response")
    return dict(zip(WATCH, parts))


def expected_plan():
    out = db("EXPLAIN " + SQL + ";")
    lines = [line.split("\t") for line in out.splitlines()]
    if len(lines) != 1 or len(lines[0]) < 7:
        raise Error("unexpected EXPLAIN shape")
    # EXPLAIN columns: id select_type table partitions type possible_keys key...
    return lines[0][6]


def baseline():
    totals = db("SELECT (SELECT COUNT(*) FROM orders), "
                "(SELECT COUNT(*) FROM orderguard.orders), "
                "(SELECT COUNT(*) FROM orders WHERE merchant_id=88), "
                "@@GLOBAL.local_infile;").split("\t")
    if totals != ["500000", "5", "25000", "0"]:
        raise Error("database baseline differs from verified 500k/5/25k/OFF")
    if globals_read()["local_infile"] != "0":
        raise Error("local_infile unexpectedly enabled")


def read_state():
    if not STATE.exists() and not STATE.is_symlink():
        return None
    st = STATE.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
            or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1):
        raise Error("unsafe M01 state file", 3)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Error("duplicate M01 state field", 3)
            result[key] = value
        return result
    obj = json.loads(STATE.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if obj.get("id") != "M01" or not isinstance(obj.get("globals"), dict):
        raise Error("M01 state is invalid", 3)
    return obj


def write_state(obj):
    # O_EXCL protects existing state and prevents following symlinks.
    fd = os.open(STATE, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    d = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(d)
    finally:
        os.close(d)


def visibility(value):
    if value not in ("VISIBLE", "INVISIBLE"):
        raise Error("invalid visibility target", 3)
    db("SET SESSION lock_wait_timeout=10; "
       "ALTER TABLE orders ALTER INDEX idx_merchant_status_created " + value + ";")


def check():
    baseline()
    visible = index_rows()
    plan = expected_plan()
    if visible == "YES" and plan == INDEX:
        print("PASS: M01 healthy, index visible and optimizer uses it")
        return 0
    if visible == "NO" and plan != INDEX:
        print("FAIL: M01 injected, target index invisible; plan uses", plan)
        return 1
    raise Error("index visibility and optimizer plan disagree")


def inject():
    baseline()
    if read_state() is not None:
        raise Error("M01 state already exists: refusing reinjection", 3)
    if index_rows() != "YES" or expected_plan() != INDEX:
        raise Error("initial index/plan not healthy; refusing injection", 3)
    watched = globals_read()
    write_state({"id": "M01", "globals": watched})
    visibility("INVISIBLE")
    if index_rows() != "NO" or expected_plan() == INDEX:
        # Attempt targeted recovery, leave state for operator inspection.
        visibility("VISIBLE")
        raise Error("injection verification failed; restored target visibility")
    if globals_read() != watched:
        raise Error("global settings changed externally during injection")
    print("PASS: M01 injected; target index INVISIBLE; global settings untouched")
    return 0


def restore():
    baseline()
    saved = read_state()
    # No automatic global slow-log restoration: this drill never writes them.
    if index_rows() == "NO":
        if saved is None:
            raise Error("index invisible but no M01 state: refusing to alter unknown change", 3)
        visibility("VISIBLE")
    if index_rows() != "YES" or expected_plan() != INDEX:
        raise Error("index not healthy after restore")
    if saved and globals_read() != saved["globals"]:
        raise Error("global MySQL settings drifted externally; inspect manually")
    if saved:
        STATE.unlink()
    print("PASS: M01 index visible and healthy; reset is idempotent")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["inject", "check", "reset", "solution"])
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    safety()
    require_dir()
    fd = acquire_lock()
    try:
        if args.dry_run:
            baseline()
            print("DRY RUN: validated environment, index:", index_rows())
            return 0
        if args.action == "inject":
            return inject()
        if args.action == "check":
            return check()
        return restore()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Error as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(exc.code)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("FAIL: local I/O or state error (details omitted)", file=sys.stderr)
        sys.exit(2)
