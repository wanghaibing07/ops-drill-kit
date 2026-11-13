#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guarded M02-B real MySQL deadlock drill for Rocky Linux / Python 3.9."""

import argparse
import contextlib
import hashlib
import io
import re
import fcntl
import json
import os
import pwd
import grp
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pymysql

PROJECT = Path("/opt/ops-drill-kit")
ADMIN_CNF = Path("/etc/opsdrill/mysql-admin.cnf")
WRITER_CNF = Path("/etc/opsdrill/mysql-m02-writer.cnf")
LAB_MARKER = Path("/etc/opsdrill-lab")
STATE_DIR = Path("/var/lib/opsdrill/m02-deadlock")
STATE_FILE = STATE_DIR / "state.json"
LOCK_FILE = Path("/run/lock/opsdrill-m02-deadlock.lock")
EVIDENCE_DIR = PROJECT / "evidence"

DB_NAME = "orderguard_stage3"
WRITER_USER = "orderguard_m02_writer"
TARGET_IDS = (10086, 10087)
BASELINE = {10086: 2, 10087: 3}
WRITE_STATUS = 4
SESSION_LOCK_TIMEOUT = 8
EDGE_TIMEOUT = 5
WORKER_TIMEOUT = 12


class DrillError(RuntimeError):
    pass


def die(message):
    raise DrillError(message)


def require_root_and_lab():
    if os.geteuid() != 0:
        die("必须使用 sudo 执行")
    result = subprocess.run(
        ["systemd-detect-virt", "--vm"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, timeout=5, check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "vmware":
        die("拒绝操作：当前环境不是可识别的 VMware")
    try:
        st = os.lstat(LAB_MARKER)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
            die("项目 marker 类型或所有者异常")
        marker = LAB_MARKER.read_text(encoding="ascii").strip()
    except OSError:
        die("项目 marker 不存在或不可读取")
    if marker != "ops-drill-kit":
        die("项目 marker 不匹配")


def check_dir(path, uid=0, gid=0, mode=0o700):
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        die("目录类型错误：" + str(path))
    if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, mode):
        die("目录所有者或权限错误：" + str(path))


def check_file(path, uid=0, gid=0, mode=0o600):
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        die("文件类型或硬链接数异常：" + str(path))
    if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, mode):
        die("文件所有者或权限错误：" + str(path))


def acquire_lock():
    LOCK_FILE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(
        LOCK_FILE,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
        os.close(fd)
        die("演练锁文件元数据异常")
    os.fchmod(fd, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        die("另一个 M02 操作正在运行")
    return fd


def connect_mysql(option_file, autocommit):
    check_dir(option_file.parent, 0, 0, 0o700)
    check_file(option_file)
    try:
        return pymysql.connect(
            read_default_file=str(option_file),
            read_default_group="client",
            database=DB_NAME,
            charset="utf8mb4",
            autocommit=autocommit,
            connect_timeout=5,
            read_timeout=20,
            write_timeout=20,
        )
    except Exception:
        die("MySQL 连接失败；认证信息已隐藏")


def connect_admin():
    return connect_mysql(ADMIN_CNF, True)


def connect_writer():
    return connect_mysql(WRITER_CNF, False)


def one(conn, sql, params=()):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def global_snapshot(conn):
    row = one(conn, """
        SELECT @@GLOBAL.server_uuid, @@GLOBAL.version,
               @@GLOBAL.log_bin, @@GLOBAL.innodb_deadlock_detect,
               @@GLOBAL.innodb_lock_wait_timeout
    """)
    return {
        "server_uuid": str(row[0]),
        "version": str(row[1]),
        "log_bin": int(row[2]),
        "deadlock_detect": int(row[3]),
        "lock_wait_timeout": int(row[4]),
    }


def target_status(conn):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, order_status FROM orders "
            "WHERE id IN (%s,%s) ORDER BY id",
            TARGET_IDS,
        )
        rows = cur.fetchall()
    result = {int(r[0]): int(r[1]) for r in rows}
    if set(result) != set(TARGET_IDS):
        die("目标订单不存在")
    return result


def transaction_count(conn, ids=None):
    if ids is None:
        row = one(conn, "SELECT COUNT(*) FROM information_schema.innodb_trx")
    elif not ids:
        return 0
    else:
        marks = ",".join(["%s"] * len(ids))
        row = one(
            conn,
            "SELECT COUNT(*) FROM information_schema.innodb_trx "
            "WHERE trx_mysql_thread_id IN (" + marks + ")",
            tuple(ids),
        )
    return int(row[0])


def wait_count(conn, ids=None):
    if ids is None:
        row = one(conn, "SELECT COUNT(*) FROM sys.innodb_lock_waits")
    elif not ids:
        return 0
    else:
        marks = ",".join(["%s"] * len(ids))
        row = one(
            conn,
            "SELECT COUNT(*) FROM sys.innodb_lock_waits "
            "WHERE waiting_pid IN (" + marks + ") "
            "OR blocking_pid IN (" + marks + ")",
            tuple(ids + ids),
        )
    return int(row[0])


def wait_edge(conn, waiting_pid, blocking_pid):
    row = one(conn, """
        SELECT waiting_pid, blocking_pid, wait_age_secs,
               locked_table, locked_index,
               waiting_lock_mode, blocking_lock_mode
        FROM sys.innodb_lock_waits
        WHERE waiting_pid=%s AND blocking_pid=%s
    """, (waiting_pid, blocking_pid))
    if row is None:
        return None
    return {
        "waiting_pid": int(row[0]),
        "blocking_pid": int(row[1]),
        "wait_age_secs": int(row[2]),
        "locked_table": str(row[3]),
        "locked_index": str(row[4]),
        "waiting_lock_mode": str(row[5]),
        "blocking_lock_mode": str(row[6]),
    }


def ps_writer_threads(conn, aid, bid):
    with conn.cursor() as cur:
        cur.execute("SELECT THREAD_ID, PROCESSLIST_ID, PROCESSLIST_USER, PROCESSLIST_DB, TYPE "
                    "FROM performance_schema.threads WHERE PROCESSLIST_ID IN (%s,%s)", (aid, bid))
        rows = cur.fetchall()
    result = {}
    for tid, pid, user, database, kind in rows:
        if int(pid) not in (aid, bid) or user != WRITER_USER or database != DB_NAME or kind != "FOREGROUND":
            die("P_S Writer 线程身份不匹配")
        result[int(pid)] = int(tid)
    if len(rows) != 2 or set(result) != {aid, bid} or len(set(result.values())) != 2:
        die("P_S Writer 线程不唯一")
    return result


def validate_ps_edge(row, aid, bid, tids):
    if row is None:
        return None
    (engine, req_tid, blk_tid, req_trx, blk_trx, req_pid, blk_pid,
     req_engine, req_trx_lock, req_schema, req_table, req_index, req_type, req_mode, req_status, req_data,
     blk_engine, blk_trx_lock, blk_schema, blk_table, blk_index, blk_type, blk_mode, blk_status, blk_data) = row
    expected = (engine == req_engine == blk_engine == "INNODB"
                and int(req_tid) == tids[aid] and int(blk_tid) == tids[bid]
                and int(req_pid) == aid and int(blk_pid) == bid
                and req_trx == req_trx_lock and blk_trx == blk_trx_lock
                and req_schema == blk_schema == DB_NAME and req_table == blk_table == "orders"
                and req_index == blk_index == "PRIMARY" and req_type == blk_type == "RECORD"
                and req_mode == blk_mode == "X,REC_NOT_GAP"
                and req_status == "WAITING" and blk_status == "GRANTED"
                and str(req_data) == str(blk_data) == "10087")
    if not expected:
        die("P_S 等待边身份、目标或锁状态不符合契约")
    return {"waiting_pid": aid, "blocking_pid": bid, "waiting_thread_id": tids[aid],
            "blocking_thread_id": tids[bid], "locked_table": DB_NAME + ".orders",
            "locked_index": req_index, "waiting_lock_mode": req_mode,
            "blocking_lock_mode": blk_mode, "target_primary_key": 10087,
            "observation_source": "performance_schema"}


def ps_wait_edge(conn, aid, bid, tids):
    sql = """
        SELECT w.ENGINE, w.REQUESTING_THREAD_ID, w.BLOCKING_THREAD_ID,
               w.REQUESTING_ENGINE_TRANSACTION_ID, w.BLOCKING_ENGINE_TRANSACTION_ID,
               rt.PROCESSLIST_ID, bt.PROCESSLIST_ID,
               r.ENGINE, r.ENGINE_TRANSACTION_ID, r.OBJECT_SCHEMA, r.OBJECT_NAME,
               r.INDEX_NAME, r.LOCK_TYPE, r.LOCK_MODE, r.LOCK_STATUS, r.LOCK_DATA,
               b.ENGINE, b.ENGINE_TRANSACTION_ID, b.OBJECT_SCHEMA, b.OBJECT_NAME,
               b.INDEX_NAME, b.LOCK_TYPE, b.LOCK_MODE, b.LOCK_STATUS, b.LOCK_DATA
        FROM performance_schema.data_lock_waits w
        JOIN performance_schema.threads rt ON rt.THREAD_ID=w.REQUESTING_THREAD_ID
        JOIN performance_schema.threads bt ON bt.THREAD_ID=w.BLOCKING_THREAD_ID
        JOIN performance_schema.data_locks r ON r.ENGINE=w.ENGINE AND r.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID
        JOIN performance_schema.data_locks b ON b.ENGINE=w.ENGINE AND b.ENGINE_LOCK_ID=w.BLOCKING_ENGINE_LOCK_ID
        WHERE rt.PROCESSLIST_ID=%s AND bt.PROCESSLIST_ID=%s
    """
    with conn.cursor() as cur:
        cur.execute(sql, (aid, bid))
        rows = cur.fetchall()
    if len(rows) > 1:
        die("P_S 返回多个等待边，拒绝模糊判定")
    return validate_ps_edge(rows[0] if rows else None, aid, bid, tids)


def ps_wait_count(conn, tids=None):
    if tids is None:
        return int(one(conn, "SELECT COUNT(*) FROM performance_schema.data_lock_waits")[0])
    if not tids:
        return 0
    marks = ",".join(["%s"] * len(tids))
    return int(one(conn, "SELECT COUNT(*) FROM performance_schema.data_lock_waits "
                   "WHERE REQUESTING_THREAD_ID IN (" + marks + ") OR BLOCKING_THREAD_ID IN (" + marks + ")",
                   tuple(tids + tids))[0])


def state_ps_wait_count(conn, state):
    tids = state.get("thread_ids")
    if tids is None:
        return ps_wait_count(conn)
    if not isinstance(tids, dict) or set(tids) != {"A", "B"}:
        die("状态中的线程标识异常")
    values = [int(tids["A"]), int(tids["B"])]
    if min(values) <= 0 or values[0] == values[1]:
        die("状态中的线程标识无效")
    return ps_wait_count(conn, values)


def bounded_recovery(conn, ids, tids, expected, timeout=3.0, interval=0.1):
    deadline = time.monotonic() + timeout
    observations = []
    consecutive = 0
    while True:
        sample = {"status": target_status(conn), "transactions": transaction_count(conn, ids),
                  "waits": ps_wait_count(conn, tids)}
        observations.append(sample)
        if sample["status"] == expected and sample["transactions"] == 0 and sample["waits"] == 0:
            consecutive += 1
            if consecutive >= 2:
                return True, observations
        else:
            consecutive = 0
        if time.monotonic() >= deadline:
            return False, observations
        time.sleep(interval)


def validate_writer(conn):
    row = one(conn, "SELECT CONNECTION_ID(), CURRENT_USER(), DATABASE()")
    connection_id = int(row[0])
    if str(row[1]) != WRITER_USER + "@localhost" or str(row[2]) != DB_NAME:
        die("Writer 会话身份或数据库不匹配")
    with conn.cursor() as cur:
        cur.execute("SET SESSION innodb_lock_wait_timeout=%s",
                    (SESSION_LOCK_TIMEOUT,))
        cur.execute("SELECT @@SESSION.innodb_lock_wait_timeout")
        if int(cur.fetchone()[0]) != SESSION_LOCK_TIMEOUT:
            die("会话锁等待超时设置未生效")
    return connection_id


def update_status(conn, order_id):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE orders SET order_status=%s WHERE id=%s",
            (WRITE_STATUS, order_id),
        )
        affected = int(cur.rowcount)
    if affected != 1:
        die("目标 UPDATE 影响行数不是 1")
    return affected


def rollback(conn):
    if conn is None:
        return False
    try:
        conn.rollback()
        return True
    except Exception:
        return False


def close(conn):
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def write_state(state):
    check_dir(STATE_DIR)
    if os.path.lexists(STATE_FILE):
        check_file(STATE_FILE)
    fd, name = tempfile.mkstemp(prefix=".m02-", dir=str(STATE_DIR))
    temp = Path(name)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        data = (json.dumps(state, sort_keys=True, indent=2) + "\n").encode()
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, STATE_FILE)
        dfd = os.open(STATE_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def read_state():
    check_file(STATE_FILE)
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        die("状态文件无法解析")
    if state.get("kind") != "m02-deadlock":
        die("状态文件契约不匹配")
    return state


def write_evidence(evidence):
    devops = pwd.getpwnam("devops")
    devops_gid = grp.getgrnam("devops").gr_gid
    check_dir(EVIDENCE_DIR, devops.pw_uid, devops_gid, 0o755)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = EVIDENCE_DIR / ("m02-deadlock-" + stamp + ".json")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o640)
    try:
        os.fchown(fd, devops.pw_uid, devops_gid)
        os.fchmod(fd, 0o640)
        payload = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return path


def read_evidence(path, expected_sha256=None):
    if path.parent != EVIDENCE_DIR:
        die("证据路径超出 evidence 目录")
    devops = pwd.getpwnam("devops")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) !=
                (devops.pw_uid, grp.getgrnam("devops").gr_gid, 0o640) or st.st_size > 1048576):
            die("证据文件元数据异常")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(1048577)
        if len(raw) > 1048576:
            die("证据文件过大")
        if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
            die("证据摘要不匹配")
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        die("证据文件无法解析")
    finally:
        if fd >= 0:
            os.close(fd)


def preflight(admin):
    snapshot = global_snapshot(admin)
    if snapshot["log_bin"] != 1:
        die("GLOBAL log_bin 必须保持 ON")
    if snapshot["deadlock_detect"] != 1:
        die("innodb_deadlock_detect 必须保持 ON")
    if transaction_count(admin) != 0:
        die("检测到活动事务，拒绝注入")
    if ps_wait_count(admin) != 0:
        die("检测到已有锁等待，拒绝注入")
    statuses = target_status(admin)
    if statuses != BASELINE:
        die("目标订单状态不是固定种子基线 2/3")
    return snapshot, statuses


def inject(owned_run_id=None):
    if os.path.lexists(STATE_FILE):
        previous = read_state()
        if previous.get("phase") != "reset-completed":
            die("状态文件已存在；先执行 check/status/reset")
        # An unowned wrapper must never replace a CLI-owned completion record.
        if previous.get("owner_run_id") is not None and owned_run_id is None:
            die("上轮状态属于 CLI；拒绝由无归属入口覆盖")

    admin = a = b = None
    worker = None
    a_done = threading.Event()
    a_result = {}
    b_result = {}
    state = None
    snapshot = initial = None
    ids = []
    edge = None
    rollback_a = rollback_b = False
    failure = None

    try:
        admin = connect_admin()
        snapshot, initial = preflight(admin)

        a = connect_writer()
        b = connect_writer()
        aid = validate_writer(a)
        bid = validate_writer(b)
        if aid == bid:
            die("两个 Writer 连接不是独立会话")
        ids = [aid, bid]
        tids = ps_writer_threads(admin, aid, bid)

        state = {
            "kind": "m02-deadlock",
            "phase": "sessions-ready",
            "server_uuid": snapshot["server_uuid"],
            "connection_ids": ids,
            "thread_ids": {"A": tids[aid], "B": tids[bid]},
            "target_ids": list(TARGET_IDS),
            "initial_status": {str(k): v for k, v in initial.items()},
            "started_at": datetime.now(timezone.utc).isoformat(),
            "contains_credentials": False,
            "contains_raw_sql": False,
        }
        if owned_run_id is not None:
            state["owner_run_id"] = owned_run_id
        write_state(state)

        a.begin()
        b.begin()
        update_status(a, 10086)
        update_status(b, 10087)
        state["phase"] = "first-locks-held"
        write_state(state)

        def request_a_second_lock():
            try:
                a_result["affected"] = update_status(a, 10087)
            except Exception as exc:
                a_result["error_code"] = (
                    int(exc.args[0]) if exc.args and isinstance(exc.args[0], int)
                    else None
                )
                a_result["error_type"] = type(exc).__name__
            finally:
                a_done.set()

        worker = threading.Thread(
            target=request_a_second_lock,
            name="m02-session-a",
            daemon=True,
        )
        worker.start()

        deadline = time.monotonic() + EDGE_TIMEOUT
        while time.monotonic() < deadline:
            edge = ps_wait_edge(admin, aid, bid, tids)
            if edge is not None or a_done.is_set():
                break
            time.sleep(0.05)

        if edge is None:
            state["diagnostics"] = {
                "a_done_at_timeout": a_done.is_set(),
                "a_error_code_at_timeout": a_result.get("error_code"),
                "a_error_type_at_timeout": a_result.get("error_type"),
                "a_affected_at_timeout": a_result.get("affected"),
            }
            with admin.cursor() as cur:
                cur.execute("SELECT waiting_pid, blocking_pid, locked_table, locked_index "
                            "FROM sys.innodb_lock_waits WHERE waiting_pid IN (%s,%s) "
                            "OR blocking_pid IN (%s,%s)", (aid, bid, aid, bid))
                state["diagnostics"]["related_edges"] = [list(r) for r in cur.fetchall()]
            die("未观察到 A 等待 B 的真实锁关系")

        table_name = edge["locked_table"].replace("`", "").replace(" ", "").lower()
        if table_name != "orderguard_stage3.orders" or edge["locked_index"] != "PRIMARY":
            die("等待关系不属于目标表的主键锁")
        if (edge["waiting_lock_mode"] != "X,REC_NOT_GAP"
                or edge["blocking_lock_mode"] != "X,REC_NOT_GAP"):
            die("锁模式与预期不符")

        state["phase"] = "a-waiting-on-b"
        state["first_wait_edge"] = edge
        write_state(state)

        try:
            b_result["affected"] = update_status(b, 10086)
        except Exception as exc:
            b_result["error_code"] = (
                int(exc.args[0]) if exc.args and isinstance(exc.args[0], int)
                else None
            )
            b_result["error_type"] = type(exc).__name__

        if not a_done.wait(WORKER_TIMEOUT):
            die("Session A 未在限定时间内返回")

        victims = []
        if a_result.get("error_code") == 1213:
            victims.append("A")
        if b_result.get("error_code") == 1213:
            victims.append("B")
        if len(victims) != 1:
            die("未捕获到恰好一个真实 MySQL 1213")

        victim = victims[0]
        survivor = "B" if victim == "A" else "A"
        survivor_result = b_result if survivor == "B" else a_result
        if survivor_result.get("affected") != 1:
            die("存活事务的第二次 UPDATE 未成功")

        state["phase"] = "deadlock-observed"
        state["deadlock"] = {
            "error_code": 1213,
            "victim_session": victim,
            "survivor_session": survivor,
        }
        write_state(state)

    except BaseException as exc:
        failure = exc

    finally:
        # Release B first; A can then leave its blocking UPDATE.
        rollback_b = rollback(b)
        if worker is not None:
            worker.join(timeout=WORKER_TIMEOUT + 2)

        if worker is not None and worker.is_alive():
            # Force disconnect to release MySQL-side locks if the worker hung.
            close(a)
            a = None
            worker.join(timeout=3)

        if worker is None or not worker.is_alive():
            rollback_a = rollback(a)

        close(a)
        close(b)

    if failure is not None:
        if state is not None:
            state.setdefault("diagnostics", {}).update({
                "a_done_after_cleanup": a_done.is_set(),
                "a_error_code_after_cleanup": a_result.get("error_code"),
                "a_error_type_after_cleanup": a_result.get("error_type"),
                "a_affected_after_cleanup": a_result.get("affected"),
            })
            state["phase"] = "failed"
            state["failure_type"] = type(failure).__name__
            state["rollback_a_returned"] = rollback_a
            state["rollback_b_returned"] = rollback_b
            write_state(state)
        close(admin)
        if isinstance(failure, DrillError):
            raise failure
        if isinstance(failure, KeyboardInterrupt):
            raise failure
        die("注入失败；已尝试回滚，保留状态供恢复检查")

    if not rollback_a or not rollback_b:
        state["phase"] = "needs-recovery"
        write_state(state)
        close(admin)
        die("至少一个连接未能确认显式 ROLLBACK")

    state["phase"] = "recovery-checking"
    write_state(state)
    try:
        verified, observations = bounded_recovery(admin, ids, [tids[aid], tids[bid]], initial)
        after = global_snapshot(admin)
    except BaseException as exc:
        state["phase"] = "needs-recovery"
        state["recovery_error_type"] = type(exc).__name__
        write_state(state)
        close(admin)
        raise
    last = observations[-1]
    final_status, active, waits = last["status"], last["transactions"], last["waits"]
    state["recovery_observations"] = observations
    if not verified:
        state["phase"] = "needs-recovery"
        write_state(state)
        close(admin)
        die("回滚后状态验证失败；保留状态文件")

    if any(after[key] != snapshot[key] for key in ("server_uuid", "log_bin", "lock_wait_timeout", "deadlock_detect")):
        state["phase"] = "needs-recovery"
        write_state(state)
        close(admin)
        die("MySQL 身份或全局配置发生变化")

    evidence = {
        "schema_version": 1,
        "experiment": "M02-B",
        "result": "PASS",
        "started_at": state["started_at"],
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "mysql": {
            "version": snapshot["version"],
            "server_uuid": snapshot["server_uuid"],
            "global_log_bin_before": snapshot["log_bin"],
            "global_log_bin_after": after["log_bin"],
            "global_lock_wait_timeout_before": snapshot["lock_wait_timeout"],
            "global_lock_wait_timeout_after": after["lock_wait_timeout"],
        },
        "database": DB_NAME,
        "table": "orders",
        "target_ids": list(TARGET_IDS),
        "initial_status": {str(k): v for k, v in initial.items()},
        "sessions": {
            "A": {"connection_id": aid, "first_lock": 10086, "second_lock": 10087},
            "B": {"connection_id": bid, "first_lock": 10087, "second_lock": 10086},
        },
        "first_wait_edge": edge,
        "deadlock": {
            "error_code": 1213,
            "victim_session": victim,
            "survivor_session": survivor,
            "survivor_update_affected": 1,
        },
        "recovery": {
            "session_a_rollback": rollback_a,
            "session_b_rollback": rollback_b,
            "final_status": {str(k): v for k, v in final_status.items()},
            "active_target_transactions": active,
            "remaining_target_waits": waits,
        },
        "recovery_observations": observations,
        "sensitive_material_included": False,
        "raw_session_sql_included": False,
    }

    if owned_run_id is not None:
        evidence["owner_run_id"] = owned_run_id
    evidence_path = write_evidence(evidence)
    if owned_run_id is not None:
        # The evidence is devops-owned; bind its exact bytes in root-owned state.
        state["evidence_sha256"] = hashlib.sha256(
            (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
        ).hexdigest()
    state["phase"] = "completed"
    state["evidence_path"] = str(evidence_path)
    state["rollback_a_returned"] = rollback_a
    state["rollback_b_returned"] = rollback_b
    write_state(state)
    close(admin)

    print("PASS: 捕获真实 MySQL 1213")
    print("victim_session:", victim)
    print("survivor_session:", survivor)
    print("PASS: A、B 均已显式 ROLLBACK")
    print("PASS: 目标订单恢复到基线")
    print("PASS: 本轮活动事务和锁等待均为 0")
    print("evidence:", evidence_path)


def check():
    if not os.path.lexists(STATE_FILE):
        die("状态文件不存在")
    state = read_state()
    if (state.get("phase") != "completed" and not
            (state.get("phase") == "reset-completed" and
             state.get("phase_before_reset") == "completed")):
        die("本轮没有已完成的演练证据")
    path = Path(state.get("evidence_path", ""))
    digest = state.get("evidence_sha256") if state.get("owner_run_id") is not None else None
    if state.get("owner_run_id") is not None and (not isinstance(digest, str) or
            not re.fullmatch(r"[0-9a-f]{64}", digest)):
        die("证据摘要缺失")
    evidence = read_evidence(path, digest)
    if state.get("owner_run_id") is not None and evidence.get("owner_run_id") != state["owner_run_id"]:
        die("证据归属不匹配")
    if evidence.get("result") != "PASS":
        die("证据不是 PASS")
    if evidence.get("deadlock", {}).get("error_code") != 1213:
        die("证据没有真实 1213")

    admin = connect_admin()
    try:
        snapshot = global_snapshot(admin)
        if snapshot["server_uuid"] != state["server_uuid"]:
            die("MySQL server UUID 不匹配")
        if target_status(admin) != BASELINE:
            die("目标订单未恢复到基线")
        ids = state.get("connection_ids", [])
        if transaction_count(admin, ids) != 0 or state_ps_wait_count(admin, state) != 0:
            die("本轮仍有活动事务或锁等待")
        if snapshot["log_bin"] != evidence["mysql"]["global_log_bin_after"]:
            die("GLOBAL log_bin 与证据不一致")
    finally:
        close(admin)

    print("PASS: 真实 1213 证据存在")
    print("PASS: 目标订单状态已恢复")
    print("PASS: 本轮事务和锁等待均为 0")
    print("PASS: check 只读")


def reset():
    if not os.path.lexists(STATE_FILE):
        die("状态文件不存在，无法验证 reset 归属")

    state = read_state()
    admin = connect_admin()
    try:
        snapshot = global_snapshot(admin)
        if snapshot["server_uuid"] != state.get("server_uuid"):
            die("MySQL 实例不匹配，拒绝 reset")
        if target_status(admin) != BASELINE:
            die("订单状态未恢复，拒绝 reset")
        ids = state.get("connection_ids", [])
        if transaction_count(admin, ids) != 0 or state_ps_wait_count(admin, state) != 0:
            die("本轮事务或锁等待仍存在，拒绝 reset")
    finally:
        close(admin)

    # Keep a durable root-owned completion record. It preserves evidence and
    # identity across a crash between controller completion and CLI cleanup.
    if state.get("phase") != "reset-completed":
        state["phase_before_reset"] = state.get("phase")
        state["phase"] = "reset-completed"
        write_state(state)

    print("PASS: reset 完成记录已保留")
    print("PASS: 业务数据未修改")
    print("PASS: evidence 保留")


def status():
    if not os.path.lexists(STATE_FILE):
        print("state: absent")
        return
    state = read_state()
    print("state:", "present")
    print("phase:", state.get("phase"))
    print("connection_ids:", state.get("connection_ids", []))
    print("evidence_path:", state.get("evidence_path", "not-created"))


def solution():
    print("A: lock 10086, then request 10087")
    print("B: lock 10087, then request 10086")
    print("The wait-for graph contains a cycle.")
    print("InnoDB detects the deadlock and returns error 1213.")
    print("Prevention: acquire rows in ascending primary-key order.")
    print("Retry: rollback the entire transaction, retry 1213/1205")
    print("with bounded attempts, exponential backoff and jitter.")
    print("No COMMIT, KILL or global MySQL setting changes.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=("inject", "check", "reset", "status", "solution"),
    )
    parser.add_argument("--owned-run-id")
    parser.add_argument("--require-reset-completed", action="store_true")
    args = parser.parse_args()
    if args.owned_run_id is not None and not re.fullmatch(r"[0-9a-f]{24}", args.owned_run_id):
        die("run ID 格式错误")
    if args.owned_run_id is not None and args.action not in ("inject", "check", "reset"):
        die("此操作不接受 run ID")

    if args.require_reset_completed and (args.owned_run_id is None or args.action not in ("check", "reset")):
        die("完成记录验证参数不适用于此操作")

    require_root_and_lab()
    check_dir(STATE_DIR)

    lock_fd = acquire_lock()
    try:
        if args.action in ("check", "reset"):
            if os.path.lexists(STATE_FILE):
                current = read_state()
                if current.get("owner_run_id") != args.owned_run_id:
                    die("演练归属不匹配，拒绝操作")
                if args.require_reset_completed and current.get("phase") != "reset-completed":
                    die("缺少本轮 reset 完成记录")
            else:
                die("缺少本轮状态，拒绝推断归属")
        if args.action in ("inject", "check", "reset"):
            check_file(ADMIN_CNF)
        if args.action == "inject":
            check_file(WRITER_CNF)
            if args.owned_run_id is None:
                inject()
            else:
                with contextlib.redirect_stdout(io.StringIO()):
                    inject(args.owned_run_id)
                print(json.dumps({"receipt": "M02_DEADLOCK_OWNER_V1", "run_id": args.owned_run_id}))
        elif args.action == "check":
            check()
        elif args.action == "reset":
            reset()
        elif args.action == "status":
            status()
        elif args.action == "solution":
            solution()
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DrillError as exc:
        print("FAIL:", str(exc), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("INTERRUPTED: 状态文件保留；先检查连接和事务", file=sys.stderr)
        sys.exit(130)
    except Exception:
        print("FAIL: 未预期异常；敏感信息已隐藏，状态文件保留", file=sys.stderr)
        sys.exit(1)
