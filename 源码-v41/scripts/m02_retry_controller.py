#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    from . import m02_retry_core as core
else:
    import m02_retry_core as core

base = core.base

DB = "orderguard_stage3"
WRITER = "orderguard_m02_writer"
IDS = (10086, 10087)
BASELINE = {10086: 3, 10087: 3}

STATE_DIR = Path("/var/lib/opsdrill/m02-ordered-retry")
STATE_FILE = STATE_DIR / "state.json"
EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence"


class DrillError(RuntimeError):
    pass


def admin_connect():
    conn = base.connect_admin()
    if not conn.get_autocommit():
        conn.close()
        raise DrillError("Observer autocommit 不符合要求")
    return conn


def rows(conn, sql, params=()):
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def one(conn, sql, params=()):
    result = rows(conn, sql, params)
    if len(result) != 1:
        raise DrillError("只读查询结果数量异常")
    return next(iter(result[0].values()))


def thread_info(conn, pid):
    result = rows(
        conn,
        """
        SELECT THREAD_ID, PROCESSLIST_USER,
               PROCESSLIST_DB, TYPE
        FROM performance_schema.threads
        WHERE PROCESSLIST_ID=%s
        """,
        (pid,),
    )

    if len(result) != 1:
        raise DrillError("无法唯一确认 Writer 线程")

    row = result[0]

    if (
        row["PROCESSLIST_USER"] != WRITER
        or row["PROCESSLIST_DB"] != DB
        or row["TYPE"] != "FOREGROUND"
    ):
        raise DrillError("Writer 线程身份不匹配")

    return int(row["THREAD_ID"])


def record_lock(conn, tid, order_id):
    result = rows(
        conn,
        """
        SELECT THREAD_ID, ENGINE,
               OBJECT_SCHEMA, OBJECT_NAME,
               INDEX_NAME, LOCK_TYPE,
               LOCK_MODE, LOCK_STATUS, LOCK_DATA
        FROM performance_schema.data_locks
        WHERE ENGINE='INNODB'
          AND THREAD_ID=%s
          AND OBJECT_SCHEMA=%s
          AND OBJECT_NAME='orders'
          AND INDEX_NAME='PRIMARY'
          AND LOCK_TYPE='RECORD'
          AND LOCK_DATA=%s
        """,
        (tid, DB, str(order_id)),
    )

    if len(result) != 1:
        raise DrillError("目标记录锁不存在或不唯一")

    lock = result[0]

    if (
        int(lock["THREAD_ID"]) != tid
        or lock["LOCK_MODE"] != "X,REC_NOT_GAP"
        or lock["LOCK_STATUS"] != "GRANTED"
        or str(lock["LOCK_DATA"]) != str(order_id)
    ):
        raise DrillError("目标记录锁属性不匹配")

    return {
        "thread_id": tid,
        "order_id": order_id,
        "table": DB + ".orders",
        "index": "PRIMARY",
        "lock_type": "RECORD",
        "lock_mode": "X,REC_NOT_GAP",
        "lock_status": "GRANTED",
    }


def count_record_lock(conn, tid, order_id):
    return int(one(
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
          AND LOCK_DATA=%s
        """,
        (tid, DB, str(order_id)),
    ))


def count_transaction(conn, pid):
    return int(one(
        conn,
        """
        SELECT COUNT(*) AS n
        FROM information_schema.innodb_trx
        WHERE trx_mysql_thread_id=%s
        """,
        (pid,),
    ))


def count_thread_waits(conn, tid):
    return int(one(
        conn,
        """
        SELECT COUNT(*) AS n
        FROM performance_schema.data_lock_waits
        WHERE REQUESTING_THREAD_ID=%s
           OR BLOCKING_THREAD_ID=%s
        """,
        (tid, tid),
    ))


def read_wait_edge(conn, waiting_tid, blocking_tid):
    result = rows(
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
          ON r.ENGINE=w.ENGINE
         AND r.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID

        JOIN performance_schema.data_locks b
          ON b.ENGINE=w.ENGINE
         AND b.ENGINE_LOCK_ID=w.BLOCKING_ENGINE_LOCK_ID

        JOIN performance_schema.threads rt
          ON rt.THREAD_ID=w.REQUESTING_THREAD_ID

        JOIN performance_schema.threads bt
          ON bt.THREAD_ID=w.BLOCKING_THREAD_ID

        WHERE w.ENGINE='INNODB'
          AND w.REQUESTING_THREAD_ID=%s
          AND w.BLOCKING_THREAD_ID=%s
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
        "req_data": "10087",
        "blk_data": "10087",
    }

    for key, value in expected.items():
        if str(r[key]) != str(value):
            raise DrillError("等待边验证失败：" + key)

    if (
        str(r["req_trx"]) != str(r["req_lock_trx"])
        or str(r["blk_trx"]) != str(r["blk_lock_trx"])
    ):
        raise DrillError("等待边事务 ID 不一致")

    return {
        "source": "performance_schema.data_lock_waits",
        "waiting_pid": int(r["req_pid"]),
        "blocking_pid": int(r["blk_pid"]),
        "waiting_thread_id": waiting_tid,
        "blocking_thread_id": blocking_tid,
        "table": DB + ".orders",
        "index": "PRIMARY",
        "record_id": 10087,
        "waiting_mode": r["req_mode"],
        "blocking_mode": r["blk_mode"],
        "waiting_status": r["req_status"],
        "blocking_status": r["blk_status"],
    }


def snapshot(conn):
    system = rows(
        conn,
        """
        SELECT VERSION() AS version,
               @@GLOBAL.server_uuid AS server_uuid,
               @@GLOBAL.log_bin AS log_bin,
               @@GLOBAL.innodb_deadlock_detect AS deadlock_detect,
               @@GLOBAL.innodb_lock_wait_timeout AS lock_timeout
        """
    )[0]

    order_rows = rows(
        conn,
        """
        SELECT id, order_status
        FROM orderguard_stage3.orders
        WHERE id IN (%s,%s)
        ORDER BY id
        """,
        IDS,
    )

    statuses = {
        int(r["id"]): int(r["order_status"])
        for r in order_rows
    }

    return {
        "version": system["version"],
        "server_uuid": system["server_uuid"],
        "log_bin": int(system["log_bin"]),
        "deadlock_detect": int(system["deadlock_detect"]),
        "lock_timeout": int(system["lock_timeout"]),
        "statuses": statuses,
        "active_transactions": int(one(
            conn,
            "SELECT COUNT(*) FROM information_schema.innodb_trx"
        )),
        "active_waits": int(one(
            conn,
            "SELECT COUNT(*) FROM performance_schema.data_lock_waits"
        )),
    }


def take_snapshot():
    conn = admin_connect()
    try:
        return snapshot(conn)
    finally:
        conn.close()


def wait_for_clean_snapshot(timeout=3.0, interval=0.1):
    deadline = time.monotonic() + timeout
    samples = []
    streak = 0
    while True:
        sample = take_snapshot()
        samples.append(sample)
        clean = (sample["statuses"] == BASELINE and sample["active_transactions"] == 0
                 and sample["active_waits"] == 0)
        streak = streak + 1 if clean else 0
        if streak >= 2:
            return True, samples
        if time.monotonic() >= deadline:
            return False, samples
        time.sleep(interval)


def verify_preflight(s):
    if s["statuses"] != BASELINE:
        raise DrillError("订单基线不符合预期")

    if s["active_transactions"] != 0 or s["active_waits"] != 0:
        raise DrillError("实验开始前存在活动事务或锁等待")

    if (
        s["log_bin"] != 1
        or s["deadlock_detect"] != 1
        or s["lock_timeout"] != 50
    ):
        raise DrillError("MySQL 全局配置与基线不符")


def write_state(state):
    fd, name = tempfile.mkstemp(
        prefix=".m02-retry-",
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

        os.replace(name, STATE_FILE)
        os.chown(STATE_FILE, 0, 0)
        os.chmod(STATE_FILE, 0o600)
        dfd = os.open(STATE_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_evidence(data):
    if not EVIDENCE_DIR.is_dir():
        raise DrillError("项目 evidence 目录不存在")

    if stat.S_ISLNK(os.lstat(EVIDENCE_DIR).st_mode):
        raise DrillError("evidence 目录不能是符号链接")

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )

    path = EVIDENCE_DIR / (
        "m02-ordered-retry-" + stamp + ".json"
    )

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(str(path), flags, 0o640)

    try:
        gid = grp.getgrnam("devops").gr_gid
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


def secure_state_dir():
    st = os.lstat(STATE_DIR)

    if (
        not stat.S_ISDIR(st.st_mode)
        or stat.S_ISLNK(st.st_mode)
        or st.st_uid != 0
        or st.st_gid != 0
        or stat.S_IMODE(st.st_mode) != 0o700
    ):
        raise DrillError("状态目录必须为 root:root 0700")


def close_quiet(conn):
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def run():
    if os.geteuid() != 0:
        raise DrillError("必须通过受控 root 包装器运行")

    secure_state_dir()

    if os.path.lexists(STATE_FILE):
        raise DrillError("已有状态文件，拒绝重复注入")

    events = {
        name: threading.Event()
        for name in (
            "a_locked",
            "release_a",
            "a_done",
            "b_first_lock",
            "allow_b_second_lock",
            "b_rollback_verified",
            "allow_retry",
            "abort",
            "b_done",
        )
    }

    shared = {
        "b_attempts": {},
        "a_rollback_ok": False,
    }

    state = {
        "phase": "starting",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "scenario": "M02-C real 1205 whole-transaction retry",
    }

    a_thread = None
    b_thread = None
    observer = None
    failure_type = None
    evidence_path = None

    try:
        before = take_snapshot()
        verify_preflight(before)

        state["preflight"] = before
        state["phase"] = "preflight-passed"
        write_state(state)

        # A：单独持有 10087
        def holder_worker():
            conn = None
            started = False
            rollback_ok = False

            try:
                conn = base.connect_writer()
                cid = int(base.validate_writer(conn))

                conn.begin()
                started = True

                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, order_status
                        FROM orders
                        WHERE id=%s
                        FOR UPDATE
                        """,
                        (10087,),
                    )
                    row = cur.fetchone()

                if row is None or int(row[1]) != 3:
                    raise DrillError("A 取得的订单不符合基线")

                shared["a_connection_id"] = cid
                events["a_locked"].set()

                if not events["release_a"].wait(15):
                    raise DrillError("A 等待释放超时")

                conn.rollback()
                rollback_ok = True

            except BaseException as exc:
                shared["a_error_type"] = type(exc).__name__

            finally:
                if conn is not None and started and not rollback_ok:
                    try:
                        conn.rollback()
                        rollback_ok = True
                    except Exception:
                        rollback_ok = False

                shared["a_rollback_ok"] = rollback_ok
                close_quiet(conn)
                events["a_done"].set()

        a_thread = threading.Thread(
            target=holder_worker,
            name="m02-holder-A",
        )
        a_thread.start()

        if not events["a_locked"].wait(5):
            raise DrillError("A 未成功取得 10087")

        observer = admin_connect()

        aid = shared["a_connection_id"]
        atid = thread_info(observer, aid)

        shared["a_thread_id"] = atid

        a_lock = record_lock(observer, atid, 10087)

        state["a_lock"] = a_lock
        state["phase"] = "A-holds-10087"
        write_state(state)

        # B：执行已经通过单元测试的完整事务重试核心
        def on_connection(attempt, cid):
            tid_conn = admin_connect()
            try:
                tid = thread_info(tid_conn, cid)
            finally:
                tid_conn.close()

            if attempt in shared["b_attempts"]:
                raise DrillError("B 重试连接重复")

            shared["b_attempts"][attempt] = {
                "connection_id": int(cid),
                "thread_id": int(tid),
            }

            if cid == aid or tid == atid:
                raise DrillError("A/B 连接或线程身份重复")

        def after_first_lock(attempt, cid):
            info = shared["b_attempts"][attempt]

            if attempt == 1:
                events["b_first_lock"].set()

                if not events["allow_b_second_lock"].wait(8):
                    raise DrillError("B 第一阶段锁验证超时")

            elif attempt == 2:
                check_conn = admin_connect()
                try:
                    shared["retry_first_lock"] = record_lock(
                        check_conn,
                        info["thread_id"],
                        10086,
                    )
                finally:
                    check_conn.close()

        def before_retry(attempt, code, history):
            if attempt != 1 or code != 1205:
                raise DrillError("本轮未捕获预期的真实 1205")

            info = shared["b_attempts"][1]
            bcid = info["connection_id"]
            btid = info["thread_id"]

            check_conn = admin_connect()

            try:
                deadline = time.monotonic() + 2.0
                clean_streak = 0

                while time.monotonic() < deadline:
                    lock_count = count_record_lock(
                        check_conn, btid, 10086
                    )
                    trx_count = count_transaction(
                        check_conn, bcid
                    )
                    wait_count = count_thread_waits(
                        check_conn, btid
                    )

                    clean = (
                        lock_count == 0
                        and trx_count == 0
                        and wait_count == 0
                    )

                    clean_streak = clean_streak + 1 if clean else 0

                    if clean_streak >= 2:
                        break

                    time.sleep(0.2)

                if clean_streak < 2:
                    raise DrillError("B 的整笔事务尚未完全释放")

                shared["b_rollback_verified"] = {
                    "error_code": 1205,
                    "rollback": True,
                    "lock_10086_count": 0,
                    "active_transaction_count": 0,
                    "related_wait_count": 0,
                    "consecutive_clean_checks": 2,
                }

                events["b_rollback_verified"].set()

            finally:
                check_conn.close()

            # 必须等主线程确认已观察到真实等待边
            if not events["allow_retry"].wait(8):
                raise DrillError("未获准进入重试阶段")

            if events["abort"].is_set():
                raise DrillError("等待边验收失败，拒绝重试")

            # 先释放 A，再允许核心函数创建新连接重试
            events["release_a"].set()

            if not events["a_done"].wait(6):
                raise DrillError("A 未完成 ROLLBACK")

            if not shared["a_rollback_ok"]:
                raise DrillError("A ROLLBACK 未确认")

            deadline = time.monotonic() + 2.0
            clean_streak = 0
            observations = []
            while True:
                # A fresh observer avoids retaining a stale INNODB_TRX view
                # across repeated reads on one connection.
                verify_conn = admin_connect()
                try:
                    sample = {"lock_10087": count_record_lock(verify_conn, atid, 10087),
                              "transactions": count_transaction(verify_conn, aid),
                              "waits": count_thread_waits(verify_conn, atid),
                              "thread_present": int(one(verify_conn,
                                  "SELECT COUNT(*) FROM performance_schema.threads WHERE THREAD_ID=%s AND PROCESSLIST_ID=%s",
                                  (atid, aid)))}
                    trx = rows(verify_conn, "SELECT trx_id, trx_state, trx_started, trx_mysql_thread_id "
                               "FROM information_schema.innodb_trx WHERE trx_mysql_thread_id=%s", (aid,))
                    sample["transaction_details"] = [{"id": str(r["trx_id"]), "state": r["trx_state"],
                                                       "started": str(r["trx_started"]), "pid": int(r["trx_mysql_thread_id"])}
                                                      for r in trx]
                finally:
                    verify_conn.close()
                observations.append(sample)
                clean_streak = clean_streak + 1 if all(sample[k] == 0 for k in ("lock_10087", "transactions", "waits", "thread_present")) else 0
                if clean_streak >= 2:
                    break
                if time.monotonic() >= deadline:
                    shared["a_release_observations"] = observations
                    raise DrillError("A 的锁或事务未在期限内释放")
                time.sleep(0.2)

            shared["a_release_verified"] = True
            shared["a_release_observations"] = observations

        def business_worker():
            try:
                shared["b_result"] = (
                    core.run_ordered_transaction_with_retry(
                        max_attempts=2,
                        on_connection=on_connection,
                        after_first_lock=after_first_lock,
                        before_retry=before_retry,
                    )
                )
            except BaseException as exc:
                shared["b_error_type"] = type(exc).__name__
                if isinstance(exc, (DrillError, core.RetryFailure)):
                    shared["b_safe_reason"] = str(exc)
            finally:
                events["b_done"].set()

        b_thread = threading.Thread(
            target=business_worker,
            name="m02-business-B",
        )
        b_thread.start()

        if not events["b_first_lock"].wait(5):
            raise DrillError("B 未完成第一次锁定")

        b1 = shared["b_attempts"][1]
        bcid = b1["connection_id"]
        btid = b1["thread_id"]

        # 证明 B 已经持有 10086，A 仍持有 10087
        b_lock = record_lock(observer, btid, 10086)

        if record_lock(observer, atid, 10087) is None:
            raise DrillError("A 的阻塞锁不存在")

        state["b_first_lock"] = b_lock
        state["b_connection_id"] = bcid
        state["b_thread_id"] = btid
        state["phase"] = "A-holds-10087-B-holds-10086"
        write_state(state)

        events["allow_b_second_lock"].set()

        # 等待真实 B -> A 锁等待边，并持续到 B 回滚
        deadline = time.monotonic() + 6.0
        edge = None

        while time.monotonic() < deadline:
            edge = read_wait_edge(observer, btid, atid)

            if edge is not None:
                shared["wait_edge"] = edge

            if events["b_rollback_verified"].is_set():
                break

            if events["b_done"].is_set():
                break

            time.sleep(0.05)

        if not events["b_rollback_verified"].is_set():
            raise DrillError("未观察到 B 的 1205 回滚验收")

        if "wait_edge" not in shared:
            raise DrillError("未观察到真实 B 等待 A 的 P_S 等待边")

        state["wait_edge"] = shared["wait_edge"]
        state["b_rollback_verified"] = shared["b_rollback_verified"]
        state["phase"] = "B-rollback-verified"
        write_state(state)

        # 只有先确认等待边，才允许 callback 释放 A
        events["allow_retry"].set()

        if not events["b_done"].wait(12):
            raise DrillError("B 的完整事务重试超时")

        if not events["a_done"].wait(5):
            raise DrillError("A 清理未结束")

        if "b_error_type" in shared:
            raise DrillError("B 事务重试失败")

        result = shared.get("b_result")

        if not isinstance(result, dict) or result.get("result") != "PASS":
            raise DrillError("B 核心事务未返回 PASS")

        history = result.get("history", [])

        if len(history) != 2:
            raise DrillError("事务尝试次数不符合预期")

        if (
            history[0].get("error_code") != 1205
            or history[0].get("rollback") is not True
        ):
            raise DrillError("第一次事务未确认 1205 和完整回滚")

        if (
            history[1].get("result") != "completed_then_rolled_back"
            or history[1].get("rollback") is not True
            or history[1].get("lock_order") != [10086, 10087]
        ):
            raise DrillError("第二次事务未完整重试")

        b2 = shared["b_attempts"][2]

        if b2["connection_id"] == bcid or b2["thread_id"] == btid:
            raise DrillError("重试没有使用全新连接")

        if "retry_first_lock" not in shared:
            raise DrillError("第二次事务未确认首个锁 10086")

        if not shared.get("a_release_verified"):
            raise DrillError("A 的锁释放未通过验收")

        if not shared.get("a_rollback_ok"):
            raise DrillError("A 的 ROLLBACK 未通过验收")

        clean, recovery_samples = wait_for_clean_snapshot()
        after = recovery_samples[-1]
        state["recovery_observations"] = recovery_samples
        if not clean:
            raise DrillError("最终恢复状态不符合基线")

        for key in (
            "server_uuid",
            "log_bin",
            "deadlock_detect",
            "lock_timeout",
        ):
            if after[key] != before[key]:
                raise DrillError("MySQL 全局配置发生变化")

        evidence = {
            "schema_version": 1,
            "result": "PASS",
            "experiment": "M02-C ordered transaction and bounded retry",
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "mysql": {
                "version": before["version"],
                "server_uuid": before["server_uuid"],
            },
            "global_before": {
                k: before[k]
                for k in (
                    "log_bin",
                    "deadlock_detect",
                    "lock_timeout",
                )
            },
            "global_after": {
                k: after[k]
                for k in (
                    "log_bin",
                    "deadlock_detect",
                    "lock_timeout",
                )
            },
            "connections": {
                "A": aid,
                "B_attempt_1": bcid,
                "B_attempt_2": b2["connection_id"],
            },
            "threads": {
                "A": atid,
                "B_attempt_1": btid,
                "B_attempt_2": b2["thread_id"],
            },
            "first_attempt": {
                "error_code": 1205,
                "victim": "B",
                "full_transaction_rollback": True,
                "B_10086_lock_released_before_A_release": True,
                "active_B_transaction_after_rollback": 0,
            },
            "observed_wait_edge": shared["wait_edge"],
            "holder_A": {
                "locked_record": 10087,
                "rollback": True,
                "lock_released_before_retry": True,
                "release_observations": shared["a_release_observations"],
            },
            "retry": {
                "attempt": 2,
                "new_connection": True,
                "lock_order": [10086, 10087],
                "first_lock_10086_verified": True,
                "completed_then_rolled_back": True,
            },
            "final": {
                "statuses": after["statuses"],
                "active_transactions": after["active_transactions"],
                "active_waits": after["active_waits"],
                "business_changes_persisted": False,
            },
            "recovery_observations": recovery_samples,
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

        print("PASS: 真实 MySQL 1205 已捕获")
        print("PASS: B 的 10086 锁先于 A 释放而解除")
        print("PASS: A 已显式 ROLLBACK")
        print("PASS: B 使用新连接完整重试")
        print("PASS: 最终事务已 ROLLBACK")
        print("PASS: 订单、事务、锁等待恢复")
        print("EVIDENCE:", evidence_path)

        return 0

    except BaseException as exc:
        failure_type = type(exc).__name__
        failure_stage = state.get("phase")

        # 安全清理：不允许遗留人为持锁事务
        events["abort"].set()
        events["allow_b_second_lock"].set()
        events["allow_retry"].set()
        events["release_a"].set()

        if b_thread is not None:
            b_thread.join(timeout=10)

        if a_thread is not None:
            a_thread.join(timeout=10)

        threads_finished = (
            (a_thread is None or not a_thread.is_alive())
            and (b_thread is None or not b_thread.is_alive())
        )

        post = None

        recovery_samples = []
        try:
            observed_clean, recovery_samples = wait_for_clean_snapshot()
            post = recovery_samples[-1]
        except Exception:
            observed_clean = False

        clean = (
            threads_finished
            and post is not None
            and observed_clean
            and shared.get("a_rollback_ok", False)
        )

        state.update({
            "phase": "failed-clean" if clean else "needs-recovery",
            "failure_type": failure_type,
            "failure_stage": failure_stage,
            "safe_reason": str(exc) if isinstance(exc, DrillError) else None,
            "b_error_type": shared.get("b_error_type"),
            "b_safe_reason": shared.get("b_safe_reason"),
            "a_release_observations": shared.get("a_release_observations"),
            "postflight": post,
            "recovery_observations": recovery_samples,
            "threads_finished": threads_finished,
        })

        if os.path.isdir(STATE_DIR):
            try:
                write_state(state)
            except Exception:
                pass

        print("FAIL:", failure_type)
        print("STATE:", state["phase"])
        print("没有生成 PASS 证据")

        return 1

    finally:
        events["release_a"].set()

        if observer is not None:
            close_quiet(observer)


def recover():
    if not os.path.lexists(STATE_FILE):
        print("PASS: no pending state")
        return 0
    st = os.lstat(STATE_FILE)
    if not stat.S_ISREG(st.st_mode) or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink) != (0, 0, 0o600, 1):
        raise DrillError("状态文件元数据不安全")
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    if state.get("scenario") != "M02-C real 1205 whole-transaction retry":
        raise DrillError("状态文件契约不匹配")
    clean, observations = wait_for_clean_snapshot()
    expected = state.get("preflight", {})
    last = observations[-1]
    if not clean or any(last.get(k) != expected.get(k) for k in ("server_uuid", "log_bin", "deadlock_detect", "lock_timeout")):
        raise DrillError("恢复检查未通过；保留状态")
    STATE_FILE.unlink()
    dfd = os.open(STATE_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    print("PASS: clean state verified twice; state cleared")
    return 0


if __name__ == "__main__":
    base.require_root_and_lab()
    lock_fd = base.acquire_lock()
    try:
        if sys.argv[1:] == ["recover"]:
            secure_state_dir()
            sys.exit(recover())
        if sys.argv[1:]:
            raise DrillError("仅支持无参数运行或 recover")
        sys.exit(run())
    finally:
        os.close(lock_fd)
