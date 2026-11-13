#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
M02-C2: Two normal transactions with a unified lock order.

Environment:
    Rocky Linux 9
    Python 3.9
    MySQL 8.4
    PyMySQL 1.1.1

Only touches:
    orderguard_stage3.orders
    id 10086 and 10087

No COMMIT.
Both business transactions explicitly ROLLBACK.
"""

import os
import sys
import json
import time
import stat
import grp
import tempfile
import threading

from pathlib import Path
from datetime import datetime, timezone

import pymysql

if __package__:
    from . import m02_deadlock as guard
    from . import m02_retry_core as core
    from . import m02_retry_controller as c1
else:
    import m02_deadlock as guard
    import m02_retry_core as core
    import m02_retry_controller as c1


# ---------------------------------------------------------
# Fixed experiment boundary
# ---------------------------------------------------------

DB = "orderguard_stage3"
WRITER = "orderguard_m02_writer"

ORDER_IDS = (10086, 10087)

BASELINE = {
    10086: 3,
    10087: 3,
}

TARGET_STATUS = 4

STATE_DIR = Path(
    "/var/lib/opsdrill/m02-ordered-pair"
)

STATE_FILE = STATE_DIR / "state.json"

EVIDENCE_DIR = (
    Path(__file__).resolve().parents[1] / "evidence"
)

WAIT_POLL_INTERVAL = 0.05
CLEAN_POLL_INTERVAL = 0.20

WAIT_DEADLINE = 2.50
CLEAN_DEADLINE = 3.00

_LOCK_HANDLE = None


class DrillError(RuntimeError):
    pass


# ---------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def dict_rows(conn, sql, params=()):
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def scalar(conn, sql, params=()):
    result = dict_rows(conn, sql, params)

    if len(result) != 1:
        raise DrillError("只读查询结果不唯一")

    return next(iter(result[0].values()))


def record_event(shared, name, **fields):
    with shared["mutex"]:
        shared["timeline"].append({
            "event": name,
            "timestamp_utc": utc_now(),
            **fields,
        })


def record_mysql_error(shared, role, exc):
    shared["mysql_errors"].append({
        "role": role,
        "error_code": core.mysql_error_code(exc),
        "error_type": type(exc).__name__,
    })

    shared[role.lower() + "_error_type"] = type(exc).__name__


def secure_state_dir():
    st = os.lstat(STATE_DIR)

    if not stat.S_ISDIR(st.st_mode):
        raise DrillError("状态路径不是目录")

    if stat.S_ISLNK(st.st_mode):
        raise DrillError("状态目录不能是符号链接")

    if st.st_uid != 0 or st.st_gid != 0:
        raise DrillError("状态目录必须属于 root:root")

    if stat.S_IMODE(st.st_mode) != 0o700:
        raise DrillError("状态目录必须为 0700")


# ---------------------------------------------------------
# Atomic state file
# ---------------------------------------------------------

def write_state(state):
    fd, tmp = tempfile.mkstemp(
        prefix=".m02-c2-",
        dir=str(STATE_DIR),
    )

    try:
        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(
                state,
                f,
                ensure_ascii=True,
                sort_keys=True,
                indent=2,
            )

            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp, STATE_FILE)

        os.chown(STATE_FILE, 0, 0)
        os.chmod(STATE_FILE, 0o600)
        dfd = os.open(STATE_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# ---------------------------------------------------------
# Sanitized evidence
# ---------------------------------------------------------

def write_evidence(data):
    st = os.lstat(EVIDENCE_DIR)

    if (
        not stat.S_ISDIR(st.st_mode)
        or stat.S_ISLNK(st.st_mode)
    ):
        raise DrillError("evidence 路径不安全")

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S.%fZ"
    )

    path = EVIDENCE_DIR / (
        "m02-ordered-pair-" + stamp + ".json"
    )

    gid = grp.getgrnam("devops").gr_gid

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(str(path), flags, 0o640)

    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o640)

        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(
                data,
                f,
                ensure_ascii=True,
                sort_keys=True,
                indent=2,
            )

            f.flush()
            os.fsync(f.fileno())

    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass

        try:
            path.unlink()
        except OSError:
            pass

        raise

    return str(path)


# ---------------------------------------------------------
# Performance Schema: target wait edge on order 10086
# ---------------------------------------------------------

def read_wait_edge_10086(
    conn,
    waiting_tid,
    blocking_tid,
    waiting_pid,
    blocking_pid,
):
    result = dict_rows(
        conn,
        """
        SELECT
            w.ENGINE AS engine,

            w.REQUESTING_THREAD_ID AS req_tid,
            w.BLOCKING_THREAD_ID AS blk_tid,

            w.REQUESTING_ENGINE_TRANSACTION_ID AS req_trx,
            w.BLOCKING_ENGINE_TRANSACTION_ID AS blk_trx,

            rt.PROCESSLIST_ID AS req_pid,
            bt.PROCESSLIST_ID AS blk_pid,

            rt.PROCESSLIST_USER AS req_user,
            bt.PROCESSLIST_USER AS blk_user,

            rt.PROCESSLIST_DB AS req_db,
            bt.PROCESSLIST_DB AS blk_db,

            r.THREAD_ID AS req_lock_tid,
            b.THREAD_ID AS blk_lock_tid,

            r.ENGINE_TRANSACTION_ID AS req_lock_trx,
            b.ENGINE_TRANSACTION_ID AS blk_lock_trx,

            r.OBJECT_SCHEMA AS req_schema,
            b.OBJECT_SCHEMA AS blk_schema,

            r.OBJECT_NAME AS req_table,
            b.OBJECT_NAME AS blk_table,

            r.INDEX_NAME AS req_index,
            b.INDEX_NAME AS blk_index,

            r.LOCK_TYPE AS req_type,
            b.LOCK_TYPE AS blk_type,

            r.LOCK_MODE AS req_mode,
            b.LOCK_MODE AS blk_mode,

            r.LOCK_STATUS AS req_status,
            b.LOCK_STATUS AS blk_status,

            r.LOCK_DATA AS req_data,
            b.LOCK_DATA AS blk_data

        FROM performance_schema.data_lock_waits w

        JOIN performance_schema.data_locks r
          ON r.ENGINE = w.ENGINE
         AND r.ENGINE_LOCK_ID = w.REQUESTING_ENGINE_LOCK_ID

        JOIN performance_schema.data_locks b
          ON b.ENGINE = w.ENGINE
         AND b.ENGINE_LOCK_ID = w.BLOCKING_ENGINE_LOCK_ID

        JOIN performance_schema.threads rt
          ON rt.THREAD_ID = w.REQUESTING_THREAD_ID

        JOIN performance_schema.threads bt
          ON bt.THREAD_ID = w.BLOCKING_THREAD_ID

        WHERE w.ENGINE = 'INNODB'
          AND w.REQUESTING_THREAD_ID = %s
          AND w.BLOCKING_THREAD_ID = %s
        """,
        (waiting_tid, blocking_tid),
    )

    if not result:
        return None

    if len(result) != 1:
        raise DrillError("目标等待边不唯一")

    r = result[0]

    expected = {
        "engine": "INNODB",

        "req_tid": waiting_tid,
        "blk_tid": blocking_tid,

        "req_pid": waiting_pid,
        "blk_pid": blocking_pid,

        "req_user": WRITER,
        "blk_user": WRITER,

        "req_db": DB,
        "blk_db": DB,

        "req_lock_tid": waiting_tid,
        "blk_lock_tid": blocking_tid,

        "req_schema": DB,
        "blk_schema": DB,

        "req_table": "orders",
        "blk_table": "orders",

        "req_index": "PRIMARY",
        "blk_index": "PRIMARY",

        "req_type": "RECORD",
        "blk_type": "RECORD",

        "req_mode": "X,REC_NOT_GAP",
        "blk_mode": "X,REC_NOT_GAP",

        "req_status": "WAITING",
        "blk_status": "GRANTED",

        "req_data": "10086",
        "blk_data": "10086",
    }

    for key, expected_value in expected.items():
        if str(r[key]) != str(expected_value):
            raise DrillError(
                "10086 等待边属性不匹配：" + key
            )

    if str(r["req_trx"]) != str(r["req_lock_trx"]):
        raise DrillError("B 请求事务 ID 不一致")

    if str(r["blk_trx"]) != str(r["blk_lock_trx"]):
        raise DrillError("A 阻塞事务 ID 不一致")

    return {
        "source": "performance_schema.data_lock_waits",

        "waiting_pid": waiting_pid,
        "blocking_pid": blocking_pid,

        "waiting_thread_id": waiting_tid,
        "blocking_thread_id": blocking_tid,

        "database": DB,
        "table": "orders",
        "index": "PRIMARY",

        "record_id": 10086,

        "waiting_lock_mode": r["req_mode"],
        "blocking_lock_mode": r["blk_mode"],

        "waiting_lock_status": r["req_status"],
        "blocking_lock_status": r["blk_status"],
    }


def granted_target_record_count(conn, tid):
    return int(scalar(
        conn,
        """
        SELECT COUNT(*) AS n
        FROM performance_schema.data_locks
        WHERE ENGINE='INNODB'
          AND THREAD_ID=%s
          AND OBJECT_SCHEMA=%s
          AND OBJECT_NAME='orders'
          AND INDEX_NAME='PRIMARY'
          AND LOCK_TYPE='RECORD'
          AND LOCK_STATUS='GRANTED'
          AND LOCK_DATA IN (%s,%s)
        """,
        (
            tid,
            DB,
            str(10086),
            str(10087),
        ),
    ))


def thread_count(conn, pid, tid):
    return int(scalar(
        conn,
        """
        SELECT COUNT(*) AS n
        FROM performance_schema.threads
        WHERE THREAD_ID=%s
           OR PROCESSLIST_ID=%s
        """,
        (tid, pid),
    ))


# ---------------------------------------------------------
# Bounded recovery observation
# ---------------------------------------------------------

def wait_for_connection_clean(label, pid, tid):
    deadline = time.monotonic() + CLEAN_DEADLINE

    observations = []
    consecutive_clean = 0

    while time.monotonic() < deadline:
        observer = c1.admin_connect()

        try:
            threads = thread_count(observer, pid, tid)

            locks = {
                str(order_id): c1.count_record_lock(
                    observer,
                    tid,
                    order_id,
                )
                for order_id in ORDER_IDS
            }

            transactions = c1.count_transaction(
                observer,
                pid,
            )

            waits = c1.count_thread_waits(
                observer,
                tid,
            )

            clean = (
                threads == 0
                and all(v == 0 for v in locks.values())
                and transactions == 0
                and waits == 0
            )

            sample = {
                "observed_at_utc": utc_now(),
                "role": label,
                "thread_count": threads,
                "record_locks": locks,
                "transaction_count": transactions,
                "related_wait_count": waits,
                "clean": clean,
            }

            observations.append(sample)

        finally:
            c1.close_quiet(observer)

        if clean:
            consecutive_clean += 1
        else:
            consecutive_clean = 0

        if consecutive_clean >= 2:
            return {
                "result": "PASS",
                "interval_ms": 200,
                "required_consecutive_clean": 2,
                "observations": observations,
            }

        time.sleep(CLEAN_POLL_INTERVAL)

    raise DrillError(
        label + " 未在3秒内连续两次恢复干净"
    )


def wait_for_active_transaction(pid, tid, timeout=2.0):
    deadline = time.monotonic() + timeout
    observations = []
    consecutive = 0
    while True:
        observer = c1.admin_connect()
        try:
            sample = {"thread_count": thread_count(observer, pid, tid),
                      "transaction_count": c1.count_transaction(observer, pid),
                      "related_wait_count": c1.count_thread_waits(observer, tid)}
        finally:
            c1.close_quiet(observer)
        observations.append(sample)
        clean = sample == {"thread_count": 1, "transaction_count": 1, "related_wait_count": 0}
        consecutive = consecutive + 1 if clean else 0
        if consecutive >= 2:
            return observations
        if time.monotonic() >= deadline:
            raise DrillError("B 活动事务未在期限内连续确认")
        time.sleep(CLEAN_POLL_INTERVAL)


# ---------------------------------------------------------
# Worker A: first normal transaction
# ---------------------------------------------------------

def worker_a(events, shared):
    conn = None
    transaction_started = False
    rollback_done = False

    try:
        conn = guard.connect_writer()

        pid = int(guard.validate_writer(conn))

        shared["a_connection_id"] = pid

        core.set_session_timeout(conn)

        conn.begin()
        transaction_started = True

        shared["a_transaction_started"] = True

        statuses = {}

        # 固定顺序：10086 -> 10087
        for order_id in ORDER_IDS:
            statuses[order_id] = core.lock_one(
                conn,
                order_id,
            )

            shared["a_lock_order"].append(order_id)

            record_event(
                shared,
                "A_LOCK_GRANTED",
                order_id=order_id,
            )

        if statuses != BASELINE:
            raise DrillError("A 读取到的初始状态不符合基线")

        affected = {}

        for order_id in ORDER_IDS:
            affected[order_id] = core.update_one(
                conn,
                order_id,
            )

        if affected != {
            10086: 1,
            10087: 1,
        }:
            raise DrillError("A 更新行数不符合预期")

        current = core.read_statuses(conn)

        if current != {
            10086: TARGET_STATUS,
            10087: TARGET_STATUS,
        }:
            raise DrillError("A 事务内状态验证失败")

        shared["a_update_rows"] = affected
        shared["a_in_transaction_statuses"] = current

        record_event(
            shared,
            "A_BOTH_LOCKS_AND_UPDATES_READY",
        )

        events["a_ready"].set()

        if not events["release_a"].wait(10):
            raise DrillError("A 等待释放超时")

        if not core.rollback_checked(conn):
            raise DrillError("A 显式 ROLLBACK 失败")

        rollback_done = True
        shared["a_rollback_ok"] = True

        record_event(
            shared,
            "A_ROLLBACK_RETURNED",
        )

    except pymysql.MySQLError as exc:
        record_mysql_error(shared, "A", exc)

    except BaseException as exc:
        shared["a_error_type"] = type(exc).__name__

    finally:
        if conn is not None and transaction_started and not rollback_done:
            ok = core.rollback_checked(conn)

            shared["a_rollback_ok"] = bool(ok)

            if not ok:
                shared["cleanup_failed"] = True

        elif not transaction_started:
            shared["a_rollback_ok"] = True

        c1.close_quiet(conn)

        events["a_done"].set()


# ---------------------------------------------------------
# Worker B: second normal transaction
# ---------------------------------------------------------

def worker_b(events, shared):
    conn = None
    transaction_started = False
    rollback_done = False

    try:
        conn = guard.connect_writer()

        pid = int(guard.validate_writer(conn))

        shared["b_connection_id"] = pid

        core.set_session_timeout(conn)

        conn.begin()
        transaction_started = True

        shared["b_transaction_started"] = True

        events["b_started"].set()

        record_event(
            shared,
            "B_TRANSACTION_STARTED",
        )

        # B 首先请求 10086。
        # 此时 A 仍持有 10086 和 10087。
        first_status = core.lock_one(
            conn,
            10086,
        )

        if events["abort"].is_set():
            raise DrillError("清理期间停止 B 的后续操作")

        shared["b_first_status"] = first_status
        shared["b_lock_order"].append(10086)

        record_event(
            shared,
            "B_LOCK_GRANTED",
            order_id=10086,
        )

        events["b_first_acquired"].set()

        # 暂停，等待 Observer 确认：
        # B 只取得了 10086，尚未取得 10087。
        if not events["allow_b_second"].wait(8):
            raise DrillError("B 第二把锁等待授权超时")

        if events["abort"].is_set():
            raise DrillError("清理期间停止 B 的后续操作")

        second_status = core.lock_one(
            conn,
            10087,
        )

        shared["b_second_status"] = second_status
        shared["b_lock_order"].append(10087)

        record_event(
            shared,
            "B_LOCK_GRANTED",
            order_id=10087,
        )

        statuses_before = {
            10086: first_status,
            10087: second_status,
        }

        if statuses_before != BASELINE:
            raise DrillError("B 读取到的基线状态不符合预期")

        affected = {}

        for order_id in ORDER_IDS:
            affected[order_id] = core.update_one(
                conn,
                order_id,
            )

        if affected != {
            10086: 1,
            10087: 1,
        }:
            raise DrillError("B 更新行数不符合预期")

        current = core.read_statuses(conn)

        if current != {
            10086: TARGET_STATUS,
            10087: TARGET_STATUS,
        }:
            raise DrillError("B 事务内状态验证失败")

        shared["b_update_rows"] = affected
        shared["b_in_transaction_statuses"] = current

        events["b_updated"].set()

        record_event(
            shared,
            "B_BOTH_LOCKS_AND_UPDATES_READY",
        )

        if not events["release_b"].wait(8):
            raise DrillError("B 等待释放超时")

        if not core.rollback_checked(conn):
            raise DrillError("B 显式 ROLLBACK 失败")

        rollback_done = True
        shared["b_rollback_ok"] = True

        record_event(
            shared,
            "B_ROLLBACK_RETURNED",
        )

    except pymysql.MySQLError as exc:
        record_mysql_error(shared, "B", exc)

    except BaseException as exc:
        shared["b_error_type"] = type(exc).__name__

    finally:
        if conn is not None and transaction_started and not rollback_done:
            ok = core.rollback_checked(conn)

            shared["b_rollback_ok"] = bool(ok)

            if not ok:
                shared["cleanup_failed"] = True

        elif not transaction_started:
            shared["b_rollback_ok"] = True

        c1.close_quiet(conn)

        events["b_done"].set()


# ---------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------

def run():
    global _LOCK_HANDLE

    if os.geteuid() != 0:
        raise DrillError("必须通过 root 受控执行")

    # 复用 M02 原有 VMware、项目标记护栏。
    guard.require_root_and_lab()

    # 与 M02-B、M02-C 共用同一把 flock。
    # 保留返回对象，直到本进程结束。
    _LOCK_HANDLE = guard.acquire_lock()

    secure_state_dir()

    if os.path.lexists(STATE_FILE):
        raise DrillError(
            "已有 C2 状态文件，拒绝重复注入"
        )

    events = {
        name: threading.Event()
        for name in (
            "a_ready",
            "release_a",
            "a_done",
            "b_started",
            "b_first_acquired",
            "allow_b_second",
            "b_updated",
            "release_b",
            "b_done",
            "abort",
        )
    }

    shared = {
        "mutex": threading.Lock(),
        "timeline": [],

        "a_lock_order": [],
        "b_lock_order": [],

        "mysql_errors": [],

        "a_rollback_ok": None,
        "b_rollback_ok": None,

        "cleanup_failed": False,
    }

    state = {
        "schema_version": 1,
        "phase": "starting",
        "scenario": "M02-C2 ordered concurrent transactions",
        "started_at_utc": utc_now(),
    }

    state_created = False

    observer = None
    a_thread = None
    b_thread = None

    before = None
    after = None

    a_clean = None
    b_clean = None

    try:
        write_state(state)
        state_created = True

        # 预检复用 C1 已有契约。
        before = c1.take_snapshot()

        c1.verify_preflight(before)

        state["preflight"] = before
        state["phase"] = "preflight-passed"

        write_state(state)

        # -------------------------------------------------
        # Start A
        # -------------------------------------------------

        a_thread = threading.Thread(
            target=worker_a,
            args=(events, shared),
            name="m02-c2-worker-A",
        )

        a_thread.start()

        if not events["a_ready"].wait(5):
            raise DrillError("A 未在5秒内完成两把锁获取")

        if "a_error_type" in shared:
            raise DrillError("A 工作线程异常")

        a_pid = int(shared["a_connection_id"])

        observer = c1.admin_connect()

        a_tid = c1.thread_info(
            observer,
            a_pid,
        )

        shared["a_thread_id"] = a_tid

        # 独立确认 A 已持有两条 PRIMARY 记录锁。
        a_lock_10086 = c1.record_lock(
            observer,
            a_tid,
            10086,
        )

        a_lock_10087 = c1.record_lock(
            observer,
            a_tid,
            10087,
        )

        state["a_connection_id"] = a_pid
        state["a_thread_id"] = a_tid
        state["a_lock_10086"] = a_lock_10086
        state["a_lock_10087"] = a_lock_10087
        state["a_lock_order"] = list(shared["a_lock_order"])
        state["phase"] = "A-holds-both-records"

        write_state(state)

        # -------------------------------------------------
        # Start B
        # -------------------------------------------------

        b_thread = threading.Thread(
            target=worker_b,
            args=(events, shared),
            name="m02-c2-worker-B",
        )

        b_thread.start()

        if not events["b_started"].wait(5):
            raise DrillError("B 未成功启动事务")

        b_pid = int(shared["b_connection_id"])

        b_tid = c1.thread_info(
            observer,
            b_pid,
        )

        shared["b_thread_id"] = b_tid

        if a_pid == b_pid or a_tid == b_tid:
            raise DrillError("A/B 连接身份重复")

        # -------------------------------------------------
        # Observe B -> A waiting edge on 10086
        # -------------------------------------------------

        deadline = time.monotonic() + WAIT_DEADLINE

        edge = None

        while time.monotonic() < deadline:
            edge = read_wait_edge_10086(
                observer,
                waiting_tid=b_tid,
                blocking_tid=a_tid,
                waiting_pid=b_pid,
                blocking_pid=a_pid,
            )

            if edge is not None:
                break

            if events["b_done"].is_set():
                break

            time.sleep(WAIT_POLL_INTERVAL)

        if edge is None:
            raise DrillError(
                "未观察到 B 等待 A 的真实 10086 锁关系"
            )

        # B 在等待 10086 时，不得持有目标记录的 GRANTED 锁。
        b_granted = granted_target_record_count(
            observer,
            b_tid,
        )

        if b_granted != 0:
            raise DrillError(
                "B 等待期间意外持有目标记录锁"
            )

        # 再次确认 A 仍持有两条锁。
        c1.record_lock(observer, a_tid, 10086)
        c1.record_lock(observer, a_tid, 10087)

        state["wait_edge"] = edge
        state["b_granted_record_locks_while_waiting"] = b_granted
        state["phase"] = "B-waits-on-A-10086"

        write_state(state)

        record_event(
            shared,
            "OBSERVER_CONFIRMED_B_WAITING_ON_A_10086",
        )

        # -------------------------------------------------
        # Release A
        # -------------------------------------------------

        events["release_a"].set()

        if not events["a_done"].wait(5):
            raise DrillError("A 未完成显式 ROLLBACK")

        if shared.get("a_rollback_ok") is not True:
            raise DrillError("A ROLLBACK 未确认")

        # B 应当在 A 回滚后取得第一把锁。
        if not events["b_first_acquired"].wait(5):
            raise DrillError("B 未取得第一把锁 10086")

        # -------------------------------------------------
        # Verify B owns 10086 but not 10087
        # -------------------------------------------------

        c1.record_lock(
            observer,
            b_tid,
            10086,
        )

        b_second_lock_count = c1.count_record_lock(
            observer,
            b_tid,
            10087,
        )

        if b_second_lock_count != 0:
            raise DrillError(
                "B 尚未获准第二把锁却已持有 10087"
            )

        b_active_observations = wait_for_active_transaction(b_pid, b_tid)
        b_transaction_count = b_active_observations[-1]["transaction_count"]
        b_wait_count = b_active_observations[-1]["related_wait_count"]

        # A 的清理需要满足线程、锁、事务、等待全部归零。
        a_clean = wait_for_connection_clean(
            "A",
            a_pid,
            a_tid,
        )

        state["a_recovery"] = a_clean
        state["b_first_lock"] = {
            "order_id": 10086,
            "granted": True,
            "second_lock_10087_count": b_second_lock_count,
            "transaction_count": b_transaction_count,
            "related_wait_count": b_wait_count,
            "observations": b_active_observations,
        }

        state["phase"] = "A-clean-B-holds-10086"

        write_state(state)

        # 允许 B 获取第二把锁。
        events["allow_b_second"].set()

        # -------------------------------------------------
        # B completes its business operations
        # -------------------------------------------------

        if not events["b_updated"].wait(5):
            raise DrillError("B 未完成两笔订单更新")

        c1.record_lock(
            observer,
            b_tid,
            10086,
        )

        c1.record_lock(
            observer,
            b_tid,
            10087,
        )

        b_updated_observations = wait_for_active_transaction(b_pid, b_tid)

        if shared.get("b_in_transaction_statuses") != {
            10086: TARGET_STATUS,
            10087: TARGET_STATUS,
        }:
            raise DrillError("B 事务内状态不符合预期")

        if shared.get("b_lock_order") != list(ORDER_IDS):
            raise DrillError("B 加锁顺序不正确")

        # -------------------------------------------------
        # Explicit rollback B
        # -------------------------------------------------

        events["release_b"].set()

        if not events["b_done"].wait(5):
            raise DrillError("B 未完成显式 ROLLBACK")

        if shared.get("b_rollback_ok") is not True:
            raise DrillError("B ROLLBACK 未确认")

        b_clean = wait_for_connection_clean(
            "B",
            b_pid,
            b_tid,
        )

        # -------------------------------------------------
        # Final independent verification
        # -------------------------------------------------

        clean, final_observations = c1.wait_for_clean_snapshot()
        after = final_observations[-1]
        if not clean:
            raise DrillError("最终恢复观察未连续通过")

        if after["statuses"] != BASELINE:
            raise DrillError("最终订单状态不等于 3/3")

        if after["active_transactions"] != 0:
            raise DrillError("最终活动事务不为 0")

        if after["active_waits"] != 0:
            raise DrillError("最终活动等待不为 0")

        global_keys = (
            "server_uuid",
            "log_bin",
            "deadlock_detect",
            "lock_timeout",
        )

        for key in global_keys:
            if before[key] != after[key]:
                raise DrillError(
                    "MySQL 全局配置发生变化：" + key
                )

        if shared["a_lock_order"] != list(ORDER_IDS):
            raise DrillError("A 加锁顺序不正确")

        if shared["b_lock_order"] != list(ORDER_IDS):
            raise DrillError("B 加锁顺序不正确")

        if shared["a_update_rows"] != {
            10086: 1,
            10087: 1,
        }:
            raise DrillError("A 更新行数不正确")

        if shared["b_update_rows"] != {
            10086: 1,
            10087: 1,
        }:
            raise DrillError("B 更新行数不正确")

        if shared["mysql_errors"]:
            raise DrillError("实验出现 MySQL 错误")

        if shared.get("cleanup_failed"):
            raise DrillError("发生事务清理失败")

        if not a_clean or not b_clean:
            raise DrillError("连接恢复检查未通过")

        # -------------------------------------------------
        # PASS evidence
        # -------------------------------------------------

        evidence = {
            "schema_version": 1,

            "result": "PASS",

            "experiment": (
                "M02-C2 unified lock order "
                "with two concurrent transactions"
            ),

            "timestamp_utc": utc_now(),

            "mysql": {
                "version": before["version"],
                "server_uuid": before["server_uuid"],
            },

            "global_before": {
                key: before[key]
                for key in (
                    "log_bin",
                    "deadlock_detect",
                    "lock_timeout",
                )
            },

            "global_after": {
                key: after[key]
                for key in (
                    "log_bin",
                    "deadlock_detect",
                    "lock_timeout",
                )
            },

            "connections": {
                "A": a_pid,
                "B": b_pid,
            },

            "threads": {
                "A": a_tid,
                "B": b_tid,
            },

            "lock_order": {
                "A": shared["a_lock_order"],
                "B": shared["b_lock_order"],
            },

            "observed_wait_edge": edge,

            "B_waiting_phase": {
                "waiting_for": 10086,
                "granted_target_record_locks": b_granted,
                "held_10087": False,
            },

            "A": {
                "update_rows": shared["a_update_rows"],
                "in_transaction_statuses": (
                    shared["a_in_transaction_statuses"]
                ),
                "explicit_rollback": True,
                "recovery": a_clean,
            },

            "B": {
                "first_lock": 10086,
                "second_lock": 10087,
                "update_rows": shared["b_update_rows"],
                "in_transaction_statuses": (
                    shared["b_in_transaction_statuses"]
                ),
                "explicit_rollback": True,
                "recovery": b_clean,
                "updated_transaction_observations": b_updated_observations,
            },

            "mysql_errors": {
                "1213": 0,
                "1205": 0,
            },

            "final": {
                "statuses": after["statuses"],
                "active_transactions": after["active_transactions"],
                "active_waits": after["active_waits"],
                "business_changes_persisted": False,
            },

            "recovery_observations": final_observations,

            "timeline": shared["timeline"],

            "raw_sql_included": False,
            "credentials_included": False,
        }

        evidence_path = write_evidence(evidence)

        state.update({
            "phase": "complete",
            "result": "PASS",
            "evidence": evidence_path,
            "postflight": after,
        })

        write_state(state)

        print("PASS: A 按 10086 -> 10087 加锁")
        print("PASS: B 按 10086 -> 10087 加锁")
        print("PASS: P_S 捕获 B -> A 等待 10086")
        print("PASS: B 等待时没有持有目标记录锁")
        print("PASS: A 显式 ROLLBACK")
        print("PASS: B 依次取得 10086、10087")
        print("PASS: A/B 均完成 UPDATE 并显式 ROLLBACK")
        print("PASS: MySQL 1213=0、1205=0")
        print("PASS: 两个连接的恢复检查通过")
        print("PASS: 最终订单 3/3、事务 0、等待 0")
        print("EVIDENCE:", evidence_path)

        return 0

    except BaseException as exc:
        # -------------------------------------------------
        # Failure cleanup
        # -------------------------------------------------

        events["abort"].set()
        for name in (
            "release_a",
            "allow_b_second",
            "release_b",
        ):
            events[name].set()

        if a_thread is not None:
            a_thread.join(timeout=8)

        if b_thread is not None:
            b_thread.join(timeout=8)

        threads_finished = (
            (a_thread is None or not a_thread.is_alive())
            and (b_thread is None or not b_thread.is_alive())
        )

        recovery = {}

        if threads_finished:
            for role in ("a", "b"):
                pid = shared.get(role + "_connection_id")
                tid = shared.get(role + "_thread_id")

                if pid is None or tid is None:
                    continue

                try:
                    recovery[role.upper()] = (
                        wait_for_connection_clean(
                            role.upper(),
                            pid,
                            tid,
                        )
                    )

                except Exception as recovery_exc:
                    recovery[role.upper()] = {
                        "result": "NOT_CONFIRMED",
                        "error_type": type(recovery_exc).__name__,
                    }

        try:
            after = c1.take_snapshot()
        except Exception:
            after = None

        a_rollback_ok = (
            not shared.get("a_transaction_started", False)
            or shared.get("a_rollback_ok") is True
        )

        b_rollback_ok = (
            not shared.get("b_transaction_started", False)
            or shared.get("b_rollback_ok") is True
        )

        clean = (
            threads_finished
            and after is not None
            and after["statuses"] == BASELINE
            and after["active_transactions"] == 0
            and after["active_waits"] == 0
            and a_rollback_ok
            and b_rollback_ok
            and not shared.get("cleanup_failed")
            and all(
                item.get("result") == "PASS"
                for item in recovery.values()
            )
        )

        state.update({
            "phase": (
                "failed-clean"
                if clean
                else "needs-recovery"
            ),

            "failure_type": type(exc).__name__,
            "failure_stage": state.get("phase"),
            "safe_reason": str(exc) if isinstance(exc, (DrillError, c1.DrillError, guard.DrillError)) else None,
            "a_error_type": shared.get("a_error_type"),
            "b_error_type": shared.get("b_error_type"),

            "threads_finished": threads_finished,

            "recovery": recovery,

            "postflight": after,

            "timeline": shared["timeline"],

            "mysql_errors": shared["mysql_errors"],
        })

        if state_created:
            try:
                write_state(state)
            except Exception:
                pass

        print("FAIL:", type(exc).__name__)
        print("STATE:", state["phase"])
        print("未生成 PASS 证据")

        return 1

    finally:
        c1.close_quiet(observer)


def recover():
    guard.require_root_and_lab()
    lock_fd = guard.acquire_lock()
    try:
        secure_state_dir()
        if not os.path.lexists(STATE_FILE):
            print("PASS: no pending C2 state")
            return 0
        st = os.lstat(STATE_FILE)
        if not stat.S_ISREG(st.st_mode) or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink) != (0, 0, 0o600, 1):
            raise DrillError("C2 状态文件元数据不安全")
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if state.get("scenario") != "M02-C2 ordered concurrent transactions":
            raise DrillError("C2 状态文件契约不匹配")
        clean, samples = c1.wait_for_clean_snapshot()
        expected, last = state.get("preflight", {}), samples[-1]
        if not clean or any(last.get(k) != expected.get(k) for k in ("server_uuid", "log_bin", "deadlock_detect", "lock_timeout")):
            raise DrillError("C2 恢复检查未通过；保留状态")
        STATE_FILE.unlink()
        dfd = os.open(STATE_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        print("PASS: C2 clean state verified twice; state cleared")
        return 0
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    if sys.argv[1:] == ["recover"]:
        sys.exit(recover())
    if sys.argv[1:]:
        raise DrillError("仅支持无参数运行或 recover")
    sys.exit(run())
