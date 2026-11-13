#!/usr/bin/env python3
"""Guarded M01 slow-query-log capture for the ops-drill-kit Rocky Linux lab.

Only the target query's aggregate slow-log fields are retained. Raw slow-log
entries, SQL text, credentials, and other sessions' statements are never
written to evidence.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pymysql


ROOT = Path("/opt/ops-drill-kit")
ADMIN_CNF = Path("/etc/opsdrill/mysql-admin.cnf")
READER_PASSWORD = Path("/etc/opsdrill/orderguard-stage3-reader.password")
STATE_DIR = Path("/var/lib/opsdrill/m01-slowlog")
STATE_FILE = STATE_DIR / "state.json"
LOCK_FILE = Path("/run/lock/opsdrill-m01-slowlog.lock")
EVIDENCE_FILE = ROOT / "evidence/m01-slowlog-capture.json"
BASELINE_FILE = ROOT / "evidence/m01-after-index.json"

EXPECTED_LOG_FILE = "/var/lib/mysql/localhost-slow.log"
DATABASE = "orderguard_stage3"
READER_USER = "orderguard_stage3_reader"
SESSION_THRESHOLD = 0.000001
EXPECTED_GLOBAL_THRESHOLD = 10.0
MAX_LOG_DELTA = 8 * 1024 * 1024

# Same SELECT fields, predicates, ordering and bound values as the M01
# benchmark. The only addition at execution time is a unique SQL comment.
QUERY = (
    "SELECT id, order_no, amount_cents, created_at "
    "FROM orders "
    "WHERE merchant_id = %s "
    "AND order_status = %s "
    "AND created_at >= %s "
    "ORDER BY created_at DESC "
    "LIMIT 20"
)
QUERY_PARAMS = (88, 1, "2026-10-01 00:00:00")

SNAPSHOT_KEYS = (
    "server_uuid",
    "socket",
    "slow_query_log",
    "slow_query_log_file",
    "long_query_time",
    "log_output",
    "log_queries_not_using_indexes",
    "min_examined_row_limit",
    "general_log",
    "local_infile",
)


class SafeError(RuntimeError):
    """An error whose message is safe to display."""


def fail(message: str) -> None:
    raise SafeError(message)


def require_root() -> None:
    if os.geteuid() != 0:
        fail("必须以 root 执行")


def lstat_regular(path: Path, *, uid: Optional[int] = None,
                  gid: Optional[int] = None, mode: Optional[int] = None,
                  nlink: Optional[int] = None) -> os.stat_result:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        fail("必要文件不存在：" + str(path))
    if not stat.S_ISREG(st.st_mode):
        fail("目标不是普通文件：" + str(path))
    if uid is not None and st.st_uid != uid:
        fail("文件所有者不符合要求：" + str(path))
    if gid is not None and st.st_gid != gid:
        fail("文件组不符合要求：" + str(path))
    if mode is not None and stat.S_IMODE(st.st_mode) != mode:
        fail("文件权限不符合要求：" + str(path))
    if nlink is not None and st.st_nlink != nlink:
        fail("文件硬链接数不符合要求：" + str(path))
    return st


def validate_secret_file(path: Path) -> None:
    lstat_regular(path, uid=0, gid=0, mode=0o600, nlink=1)


def read_reader_password() -> str:
    validate_secret_file(ADMIN_CNF)
    validate_secret_file(READER_PASSWORD)
    raw = READER_PASSWORD.read_bytes()
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or b"\n" in raw or b"\r" in raw or b"\x00" in raw:
        fail("只读账号凭据格式不符合要求")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("只读账号凭据编码不符合要求")


def ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    st = os.lstat(STATE_DIR)
    if not stat.S_ISDIR(st.st_mode):
        fail("状态路径不是目录")
    if st.st_uid != 0 or st.st_gid != 0:
        fail("状态目录必须为 root:root")
    if stat.S_IMODE(st.st_mode) != 0o700:
        fail("状态目录权限必须为 0700")


def ensure_lock_dir() -> None:
    path = LOCK_FILE.parent
    st = os.stat(path)
    if not stat.S_ISDIR(st.st_mode):
        fail("锁目录异常")
    if st.st_uid != 0:
        fail("锁目录必须由 root 管理")


def acquire_lock() -> int:
    ensure_lock_dir()
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(LOCK_FILE, flags, 0o600)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
        os.close(fd)
        fail("锁文件类型或所有者异常")
    if stat.S_IMODE(st.st_mode) != 0o600:
        os.close(fd)
        fail("锁文件权限必须为 0600")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        fail("另一个 M01 慢日志任务正在执行")
    return fd


def atomic_create_json(path: Path, payload: Dict[str, Any],
                       *, mode: int = 0o600,
                       uid: int = 0, gid: int = 0) -> None:
    """Publish a new JSON file without overwriting an existing path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            data = (json.dumps(payload, ensure_ascii=True, sort_keys=True,
                               indent=2, default=str) + "\n").encode("ascii")
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temp, uid, gid)
        os.chmod(temp, mode)
        # link() fails if destination already exists; never overwrite evidence/state.
        os.link(temp, path, follow_symlinks=False)
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def read_state() -> Dict[str, Any]:
    lstat_regular(STATE_FILE, uid=0, gid=0, mode=0o600, nlink=1)
    try:
        state = json.loads(STATE_FILE.read_text(encoding="ascii"))
    except Exception:
        fail("状态文件无法安全解析，保留现场")
    if not isinstance(state, dict) or state.get("original_slow_query_log") != "0":
        fail("状态文件内容不符合恢复契约")
    return state


def mysql_admin(sql: str) -> str:
    validate_secret_file(ADMIN_CNF)
    command = [
        "mysql",
        "--defaults-extra-file=" + str(ADMIN_CNF),
        "--batch",
        "--raw",
        "--skip-column-names",
        "--execute",
        sql,
    ]
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=20, check=False,
        )
    except Exception:
        fail("MySQL 管理连接执行失败")
    if result.returncode != 0:
        fail("MySQL 管理连接失败，未输出客户端错误详情")
    return result.stdout.strip()


def admin_snapshot() -> Dict[str, str]:
    sql = """
SELECT
 @@GLOBAL.server_uuid,
 @@GLOBAL.socket,
 @@GLOBAL.slow_query_log,
 @@GLOBAL.slow_query_log_file,
 @@GLOBAL.long_query_time,
 @@GLOBAL.log_output,
 @@GLOBAL.log_queries_not_using_indexes,
 @@GLOBAL.min_examined_row_limit,
 @@GLOBAL.general_log,
 @@GLOBAL.local_infile;
"""
    output = mysql_admin(sql)
    values = output.split("\t")
    if len(values) != len(SNAPSHOT_KEYS):
        fail("MySQL 全局配置快照字段数量异常")
    return dict(zip(SNAPSHOT_KEYS, values))


def validate_preflight(snapshot: Dict[str, str]) -> None:
    if snapshot["slow_query_log"] != "0":
        fail("slow_query_log 当前不是 OFF，拒绝覆盖现状")
    if snapshot["slow_query_log_file"] != EXPECTED_LOG_FILE:
        fail("慢日志路径与已验收实际路径不一致")
    if float(snapshot["long_query_time"]) != EXPECTED_GLOBAL_THRESHOLD:
        fail("GLOBAL long_query_time 与预检基线不一致")
    expected = {
        "log_output": "FILE",
        "log_queries_not_using_indexes": "0",
        "min_examined_row_limit": "0",
        "general_log": "0",
        "local_infile": "0",
    }
    for key, value in expected.items():
        if snapshot[key] != value:
            fail("MySQL 配置与预检基线不一致：" + key)
    if not snapshot["socket"].startswith("/"):
        fail("MySQL Unix Socket 路径异常")


def read_baseline_digest() -> str:
    lstat_regular(BASELINE_FILE)
    st = os.stat(BASELINE_FILE)
    if st.st_size > 2 * 1024 * 1024:
        fail("M01 基线证据文件过大")
    try:
        data = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    except Exception:
        fail("M01 基线证据无法解析")
    digest = data.get("result_sha256") if isinstance(data, dict) else None
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        fail("m01-after-index.json 缺少有效 result_sha256")
    if data.get("returned_rows") != 20:
        fail("M01 优化后基线不是 20 行结果")
    return digest


def load_existing_result_digest():
    """Import the project's sole result_digest implementation."""
    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    try:
        from benchmark_m01 import result_digest
    except Exception:
        fail("无法导入 scripts/benchmark_m01.py 的 result_digest")
    if not callable(result_digest):
        fail("benchmark_m01.result_digest 不可调用")
    return result_digest


def verify_reader_connection(password: str, socket_path: str) -> None:
    conn = None
    try:
        conn = pymysql.connect(
            unix_socket=socket_path,
            user=READER_USER,
            password=password,
            database=DATABASE,
            charset="utf8mb4",
            connect_timeout=5,
            read_timeout=10,
            write_timeout=5,
            autocommit=True,
        )
        with conn.cursor() as cursor:
            cursor.execute("SELECT CURRENT_USER(), DATABASE()")
            account, database = cursor.fetchone()
        if not account.startswith(READER_USER + "@"):
            fail("只读连接实际账号身份不符合预期")
        if database != DATABASE:
            fail("只读连接实际数据库不符合预期")
    except SafeError:
        raise
    except Exception:
        fail("只读账号连接验证失败")
    finally:
        if conn is not None:
            conn.close()


def set_global_slow_log(enabled: bool) -> None:
    value = "ON" if enabled else "OFF"
    mysql_admin("SET GLOBAL slow_query_log = " + value)


def wait_for_log_file(path: Path, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.lexists(path):
            return
        time.sleep(0.1)
    fail("MySQL 未创建慢查询日志文件")


def open_log_snapshot(path: Path) -> Tuple[int, os.stat_result]:
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        fail("慢日志不是普通文件")
    mysql_uid = pwd.getpwnam("mysql").pw_uid
    if st.st_uid != mysql_uid:
        fail("慢日志文件所有者不是 mysql")
    if st.st_mode & 0o007:
        fail("慢日志对 other 用户开放权限")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    actual = os.fstat(fd)
    if (actual.st_dev, actual.st_ino) != (st.st_dev, st.st_ino):
        os.close(fd)
        fail("慢日志文件在打开时发生替换")
    return fd, actual


def parse_target_metrics(delta: bytes, marker: str) -> Tuple[int, Optional[Dict[str, Any]]]:
    """Stream-parse entries; retain only the target entry's four metrics."""
    marker_bytes = marker.encode("ascii")
    query_time_re = re.compile(
        rb"# Query_time:\s*([0-9.]+)\s+Lock_time:\s*([0-9.]+)"
        rb"\s+Rows_sent:\s*(\d+)\s+Rows_examined:\s*(\d+)"
    )
    current_is_target = False
    current_metrics = None
    matches = []

    def finish_entry():
        if current_is_target and current_metrics is not None:
            matches.append(current_metrics.copy())

    for line in delta.splitlines():
        if line.startswith(b"# Time:"):
            finish_entry()
            current_is_target = False
            current_metrics = None
            continue
        if marker_bytes in line:
            current_is_target = True
        match = query_time_re.search(line)
        if match:
            current_metrics = {
                "query_time_seconds": float(match.group(1)),
                "lock_time_seconds": float(match.group(2)),
                "rows_sent": int(match.group(3)),
                "rows_examined": int(match.group(4)),
            }
    finish_entry()

    if len(matches) == 1:
        return 1, matches[0]
    return len(matches), None


def read_appended_log(path: Path, initial_stat: os.stat_result,
                      offset: int) -> bytes:
    fd, current_stat = open_log_snapshot(path)
    try:
        if (current_stat.st_dev, current_stat.st_ino) != (
            initial_stat.st_dev, initial_stat.st_ino
        ):
            fail("慢日志发生轮转或文件替换")
        if current_stat.st_size < offset:
            fail("慢日志被截断")
        length = current_stat.st_size - offset
        if length > MAX_LOG_DELTA:
            fail("实验期间日志增量超过 8 MiB，拒绝读取")
        os.lseek(fd, offset, os.SEEK_SET)
        chunks = []
        remaining = length
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                fail("慢日志增量读取不完整")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def run_target_query(password: str, socket_path: str, marker: str,
                     result_digest) -> Dict[str, Any]:
    conn = None
    try:
        conn = pymysql.connect(
            unix_socket=socket_path,
            user=READER_USER,
            password=password,
            database=DATABASE,
            charset="utf8mb4",
            connect_timeout=5,
            read_timeout=20,
            write_timeout=10,
            autocommit=False,
            # Deliberately use tuple rows: benchmark_m01.result_digest
            # receives the same row shape as the original benchmark.
        )
        with conn.cursor() as cursor:
            cursor.execute("SELECT CURRENT_USER(), DATABASE()")
            account, database = cursor.fetchone()
            if not account.startswith(READER_USER + "@") or database != DATABASE:
                fail("查询连接身份或数据库不符合预期")

            cursor.execute(
                "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ"
            )
            cursor.execute("SET SESSION long_query_time = 0.000001")

            # Verify the setting on this exact connection.
            cursor.execute("""
                SELECT CONNECTION_ID(),
                       @@SESSION.long_query_time,
                       @@GLOBAL.long_query_time
            """)
            connection_id, session_lqt, global_lqt = cursor.fetchone()
            session_lqt = float(session_lqt)
            global_lqt = float(global_lqt)
            if abs(session_lqt - SESSION_THRESHOLD) > 1e-12:
                fail("当前连接 SESSION long_query_time 未生效")
            if global_lqt != EXPECTED_GLOBAL_THRESHOLD:
                fail("GLOBAL long_query_time 发生变化")

            cursor.execute(
                "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"
            )

            marked_query = QUERY.replace(
                "SELECT ",
                "SELECT /* " + marker + " */ ",
                1,
            )
            cursor.execute(marked_query, QUERY_PARAMS)
            rows = cursor.fetchall()

            if len(rows) != 20:
                fail("目标 SQL 返回行数不是 20")
            ids = [int(row[0]) for row in rows]
            if len(set(ids)) != 20:
                fail("目标 SQL 返回重复 ID")

            # Sole digest implementation: import from benchmark_m01.py.
            digest = result_digest(rows)
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                fail("benchmark_m01.result_digest 返回值格式异常")

            return {
                "connection_id": int(connection_id),
                "session_long_query_time": session_lqt,
                "global_long_query_time": global_lqt,
                "row_count": len(rows),
                "unique_ids": len(set(ids)),
                "result_sha256": digest,
            }
    except SafeError:
        raise
    except Exception:
        fail("目标 SQL 执行失败，未输出数据库异常详情")
    finally:
        if conn is not None:
            try:
                conn.rollback()
            finally:
                conn.close()


def save_recovery_receipt(run_id: str, before: Dict[str, str],
                          after: Dict[str, str]) -> Dict[str, Any]:
    drift = [
        key for key in SNAPSHOT_KEYS
        if key != "slow_query_log" and before.get(key) != after.get(key)
    ]
    receipt = {
        "run_id": run_id,
        "recovered_at": datetime.now(timezone.utc).isoformat(),
        "slow_query_log_restored": after["slow_query_log"] == "0",
        "configuration_drift_keys": drift,
        "other_global_variables_were_not_modified": True,
    }
    receipt_path = STATE_DIR / ("recovery-" + run_id + ".json")
    atomic_create_json(receipt_path, receipt, mode=0o600)
    return receipt


def recover_locked() -> Dict[str, Any]:
    if not os.path.lexists(STATE_FILE):
        return {"state_found": False, "restored": True}

    state = read_state()
    before = state["baseline"]
    current = admin_snapshot()

    if current["server_uuid"] != before["server_uuid"]:
        fail("MySQL server_uuid 不一致，拒绝自动恢复并保留状态文件")

    # Original state was OFF. Restore only this one variable.
    if current["slow_query_log"] == "1":
        set_global_slow_log(False)
    elif current["slow_query_log"] != "0":
        fail("slow_query_log 状态异常，保留恢复状态")

    after = admin_snapshot()
    if after["server_uuid"] != before["server_uuid"]:
        fail("恢复后 MySQL 实例身份发生变化")
    if after["slow_query_log"] != "0":
        fail("slow_query_log 未恢复 OFF，保留状态文件")

    receipt = save_recovery_receipt(state["run_id"], before, after)
    STATE_FILE.unlink()
    dir_fd = os.open(STATE_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return {"state_found": True, "restored": True, **receipt}


def dry_run() -> int:
    require_root()
    ensure_state_dir()
    if os.path.lexists(STATE_FILE):
        fail("存在未完成实验状态，先执行 recover")
    if os.path.lexists(EVIDENCE_FILE):
        fail("目标证据文件已存在，拒绝覆盖")
    validate_secret_file(ADMIN_CNF)
    password = read_reader_password()
    baseline_digest = read_baseline_digest()
    snapshot = admin_snapshot()
    validate_preflight(snapshot)
    verify_reader_connection(password, snapshot["socket"])
    log_path = Path(snapshot["slow_query_log_file"])
    if os.path.lexists(log_path):
        st = os.lstat(log_path)
        if not stat.S_ISREG(st.st_mode):
            fail("现有慢日志不是普通文件")
    print("DRY-RUN PASS")
    print("MySQL instance identity: verified")
    print("Reader authentication: verified")
    print("Session/global settings: not modified")
    print("Baseline SHA256: loaded from m01-after-index.json")
    print("Baseline digest:", baseline_digest)
    print("Slow query log path:", str(log_path))
    print("No global variable was changed")
    return 0


def capture() -> int:
    require_root()
    ensure_state_dir()

    if os.path.lexists(STATE_FILE):
        fail("存在未完成实验状态，先执行 recover")
    if os.path.lexists(EVIDENCE_FILE):
        fail("证据文件已存在，拒绝覆盖")

    validate_secret_file(ADMIN_CNF)
    password = read_reader_password()
    expected_digest = read_baseline_digest()
    digest_function = load_existing_result_digest()

    baseline = admin_snapshot()
    validate_preflight(baseline)
    verify_reader_connection(password, baseline["socket"])

    run_id = uuid.uuid4().hex
    marker = "M01_SLOWLOG_" + run_id
    log_path = Path(baseline["slow_query_log_file"])

    if os.path.lexists(log_path):
        st = os.lstat(log_path)
        if not stat.S_ISREG(st.st_mode):
            fail("慢日志目标已存在但不是普通文件")

    state = {
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "original_slow_query_log": "0",
        "baseline": baseline,
        "marker": marker,
    }
    atomic_create_json(STATE_FILE, state, mode=0o600)

    query_result = None
    target_metrics = None
    marker_count = 0
    initial_log_stat = None
    log_offset = None
    failure_code = None
    recovery = None

    try:
        set_global_slow_log(True)
        enabled = admin_snapshot()
        if enabled["server_uuid"] != baseline["server_uuid"]:
            fail("开启后 MySQL 实例身份变化")
        if enabled["slow_query_log"] != "1":
            fail("slow_query_log 未成功开启")
        # Refuse unexpected changes; this program changes no other global.
        for key in SNAPSHOT_KEYS:
            if key not in ("slow_query_log",) and enabled[key] != baseline[key]:
                fail("开启期间其他 MySQL 全局配置发生变化：" + key)

        wait_for_log_file(log_path)
        fd, initial_log_stat = open_log_snapshot(log_path)
        try:
            log_offset = initial_log_stat.st_size
        finally:
            os.close(fd)

        query_result = run_target_query(
            password, baseline["socket"], marker, digest_function
        )

        # Poll briefly for the target entry; never save raw log lines.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            delta = read_appended_log(log_path, initial_log_stat, log_offset)
            marker_count, target_metrics = parse_target_metrics(delta, marker)
            if marker_count:
                break
            time.sleep(0.1)

        if marker_count != 1 or target_metrics is None:
            fail("唯一目标 SQL 未在慢日志中恰好出现一次")

    except SafeError as exc:
        failure_code = str(exc)
    except BaseException:
        failure_code = "执行中断；已请求执行恢复"
        raise
    finally:
        # Recovery is attempted for normal errors, exceptions and SIGTERM.
        recovery = recover_locked()

    after = admin_snapshot()
    drift_keys = [
        key for key in SNAPSHOT_KEYS
        if key != "slow_query_log" and after[key] != baseline[key]
    ]

    checks = {
        "reader_account_verified": query_result is not None,
        "session_threshold_effective": (
            query_result is not None
            and query_result["session_long_query_time"] == SESSION_THRESHOLD
        ),
        "global_threshold_unchanged": (
            after["long_query_time"] == baseline["long_query_time"]
        ),
        "returned_20_rows": (
            query_result is not None and query_result["row_count"] == 20
        ),
        "result_digest_matches_existing_evidence": (
            query_result is not None
            and query_result["result_sha256"] == expected_digest
        ),
        "target_marker_exactly_once": marker_count == 1,
        "slow_log_rows_sent_20": (
            target_metrics is not None and target_metrics["rows_sent"] == 20
        ),
        "slow_query_log_restored_off": after["slow_query_log"] == "0",
        "other_global_config_unchanged": len(drift_keys) == 0,
        "state_cleared_after_recovery": not os.path.lexists(STATE_FILE),
    }

    passed = all(checks.values()) and failure_code is None
    evidence = {
        "experiment": "M01 slow query log capture",
        "status": "PASS" if passed else "FAIL",
        "run_id": run_id,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "database": DATABASE,
        "mysql_server_uuid": baseline["server_uuid"],
        "slow_query_log_file": str(log_path),
        "query_sha256": hashlib.sha256(QUERY.encode("utf-8")).hexdigest(),
        "marker": marker,
        "connection_id": (
            query_result["connection_id"] if query_result else None
        ),
        "session_long_query_time": (
            query_result["session_long_query_time"] if query_result else None
        ),
        "global_long_query_time_before": baseline["long_query_time"],
        "global_long_query_time_after": after["long_query_time"],
        "returned_rows": query_result["row_count"] if query_result else None,
        "result_sha256": (
            query_result["result_sha256"] if query_result else None
        ),
        "expected_result_sha256_from_m01_after_index_json": expected_digest,
        "slow_log_metrics": target_metrics,
        "matching_target_entries": marker_count,
        "configuration_drift_keys": drift_keys,
        "recovery": recovery,
        "checks": checks,
        "raw_sql_saved": False,
        "raw_slow_log_saved": False,
        "other_sessions_sql_saved": False,
        "credentials_saved": False,
        "failure_code": failure_code,
    }

    devops = pwd.getpwnam("devops")
    atomic_create_json(
        EVIDENCE_FILE, evidence, mode=0o640,
        uid=devops.pw_uid, gid=devops.pw_gid,
    )

    print("M01 slow-log capture:", evidence["status"])
    print("Returned rows:", evidence["returned_rows"])
    print("Result SHA256:", evidence["result_sha256"])
    print("Slow-log metrics:", json.dumps(target_metrics, ensure_ascii=True))
    print("slow_query_log after recovery:", after["slow_query_log"])
    print("Evidence:", EVIDENCE_FILE)

    if not passed:
        print("One or more checks failed; inspect the sanitized evidence.")
        return 2
    return 0


def status() -> int:
    require_root()
    ensure_state_dir()
    if os.path.lexists(STATE_FILE):
        state = read_state()
        print("PENDING RECOVERY")
        print("run_id:", state.get("run_id"))
        print("created_at:", state.get("created_at"))
        print("slow_query_log:", admin_snapshot()["slow_query_log"])
        return 2
    print("PASS: no pending M01 slow-log state")
    receipts = sorted(STATE_DIR.glob("recovery-*.json"))
    if receipts:
        print("latest recovery receipt:", receipts[-1].name)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("capture", "recover", "status"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    require_root()
    ensure_state_dir()
    lock_fd = acquire_lock()
    try:
        if args.action == "capture":
            if args.dry_run:
                return dry_run()
            return capture()
        if args.dry_run:
            fail("--dry-run 仅支持 capture")
        if args.action == "recover":
            result = recover_locked()
            print("RECOVERY:", json.dumps(result, ensure_ascii=True))
            return 0
        return status()
    finally:
        os.close(lock_fd)


def _signal_handler(signum, frame):
    raise KeyboardInterrupt("controlled interruption")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _signal_handler)
    try:
        sys.exit(main())
    except SafeError as exc:
        print("FAIL:", str(exc), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("INTERRUPTED: recovery was attempted; check status", file=sys.stderr)
        sys.exit(130)
    except Exception:
        # Never print third-party exception text: it may contain SQL or data.
        print("FAIL: unexpected error; inspect status and run recover if needed",
              file=sys.stderr)
        sys.exit(1)
