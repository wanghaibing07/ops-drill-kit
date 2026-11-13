#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
M02-C: Ordered transaction and bounded retry.

MySQL 8.4 / Python 3.9 / PyMySQL 1.1.1

Only touches:
    orderguard_stage3.orders
    id 10086 and 10087

Lab mode:
    Never COMMIT.
    Successful business operations are explicitly ROLLBACKed.
"""

import random
import time

import pymysql
if __package__:
    from . import m02_deadlock as base
else:
    import m02_deadlock as base


ORDER_IDS = (10086, 10087)

BASELINE_STATUS = {
    10086: 3,
    10087: 3,
}

TARGET_STATUS = 4

RETRYABLE_ERRORS = {1205, 1213}

MAX_ATTEMPTS = 3

SESSION_LOCK_TIMEOUT = 3


class RetryFailure(RuntimeError):

    def __init__(self, reason, history):
        super().__init__(reason)
        self.history = history


def mysql_error_code(exc):

    try:
        return int(exc.args[0])
    except (IndexError, TypeError, ValueError):
        return None


def rollback_checked(conn):

    try:
        conn.rollback()
        return True
    except Exception:
        return False


def lock_one(conn, order_id):

    with conn.cursor() as cur:

        cur.execute(
            """
            SELECT id, order_status
            FROM orders
            WHERE id=%s
            FOR UPDATE
            """,
            (order_id,),
        )

        row = cur.fetchone()

    if row is None:
        raise RetryFailure(
            "目标订单不存在",
            [],
        )

    if int(row[0]) != order_id:
        raise RetryFailure(
            "订单主键不匹配",
            [],
        )

    return int(row[1])


def update_one(conn, order_id):

    with conn.cursor() as cur:

        cur.execute(
            """
            UPDATE orders
            SET order_status=%s
            WHERE id=%s
            """,
            (TARGET_STATUS, order_id),
        )

        affected = int(cur.rowcount)

    if affected != 1:
        raise RetryFailure(
            "UPDATE 影响行数异常",
            [],
        )

    return affected


def read_statuses(conn):

    result = {}

    with conn.cursor() as cur:

        cur.execute(
            """
            SELECT id, order_status
            FROM orders
            WHERE id IN (%s,%s)
            ORDER BY id
            """,
            ORDER_IDS,
        )

        rows = cur.fetchall()

    for row in rows:
        result[int(row[0])] = int(row[1])

    if set(result) != set(ORDER_IDS):
        raise RetryFailure(
            "订单集合不完整",
            [],
        )

    return result


def set_session_timeout(conn):

    with conn.cursor() as cur:

        cur.execute(
            "SET SESSION innodb_lock_wait_timeout=%s",
            (SESSION_LOCK_TIMEOUT,),
        )

        cur.execute(
            "SELECT @@SESSION.innodb_lock_wait_timeout"
        )

        actual = int(cur.fetchone()[0])

    if actual != SESSION_LOCK_TIMEOUT:
        raise RetryFailure(
            "SESSION 锁等待超时设置失败",
            [],
        )


def run_ordered_transaction_with_retry(
    max_attempts=MAX_ATTEMPTS,
    on_connection=None,
    after_first_lock=None,
    before_retry=None,
):
    """
    Every retry creates a new connection and a new transaction.

    Callback parameters are intended for the controlled lab harness.
    No callback receives passwords or SQL text.
    """

    if max_attempts < 1 or max_attempts > 3:
        raise ValueError("max_attempts 必须为 1～3")

    history = []

    lock_order = tuple(sorted(ORDER_IDS))

    for attempt in range(1, max_attempts + 1):

        conn = None

        try:

            # 每次尝试使用独立的新连接
            conn = base.connect_writer()

            connection_id = base.validate_writer(conn)

            set_session_timeout(conn)

            if on_connection is not None:
                on_connection(
                    attempt,
                    connection_id,
                )

            conn.begin()

            before = {}

            # 第一阶段：严格按照主键升序取得全部行锁
            for index, order_id in enumerate(lock_order):

                before[order_id] = lock_one(
                    conn,
                    order_id,
                )

                if (
                    index == 0
                    and after_first_lock is not None
                ):
                    after_first_lock(
                        attempt,
                        connection_id,
                    )

            if before != BASELINE_STATUS:
                raise RetryFailure(
                    "事务开始时订单状态不符合基线",
                    history,
                )

            # 第二阶段：持有全部锁之后再修改
            affected = {}

            for order_id in lock_order:

                affected[order_id] = update_one(
                    conn,
                    order_id,
                )

            if affected != {
                10086: 1,
                10087: 1,
            }:
                raise RetryFailure(
                    "更新数量不符合预期",
                    history,
                )

            # 第三阶段：事务内验证业务操作
            current = read_statuses(conn)

            if current != {
                10086: TARGET_STATUS,
                10087: TARGET_STATUS,
            }:
                raise RetryFailure(
                    "事务内结果验证失败",
                    history,
                )

            # 实验模式：不提交业务变更
            if not rollback_checked(conn):
                raise RetryFailure(
                    "成功路径 ROLLBACK 失败",
                    history,
                )

            history.append({
                "attempt": attempt,
                "result": "completed_then_rolled_back",
                "connection_id": connection_id,
                "lock_order": list(lock_order),
                "affected_rows": affected,
                "rollback": True,
            })

            return {
                "result": "PASS",
                "attempts_used": attempt,
                "history": history,
                "persisted": False,
            }

        except pymysql.MySQLError as exc:

            code = mysql_error_code(exc)

            rollback_ok = rollback_checked(conn)

            history.append({
                "attempt": attempt,
                "result": "mysql_error",
                "error_code": code,
                "error_type": type(exc).__name__,
                "rollback": rollback_ok,
            })

            if not rollback_ok:
                raise RetryFailure(
                    "异常后的整个事务回滚失败",
                    history,
                )

            if code not in RETRYABLE_ERRORS:
                raise RetryFailure(
                    "非可重试 MySQL 错误",
                    history,
                )

            if attempt >= max_attempts:
                raise RetryFailure(
                    "已达到最大重试次数",
                    history,
                )

            # 测试驱动可在这里释放人为持有的锁
            if before_retry is not None:
                before_retry(
                    attempt,
                    code,
                    history,
                )

            # 有界指数退避 + 随机抖动
            ceiling = min(
                0.4,
                0.1 * (2 ** (attempt - 1)),
            )

            delay = random.uniform(
                ceiling / 2,
                ceiling,
            )

            time.sleep(delay)

        except BaseException:

            # A non-MySQL error or interruption can occur after locks are held.
            # Explicitly roll back the whole transaction before disconnecting.
            if conn is not None and not rollback_checked(conn):
                raise RetryFailure("异常路径 ROLLBACK 失败", history)
            raise

        finally:

            base.close(conn)

    raise RetryFailure(
        "事务重试异常结束",
        history,
    )
