#!/usr/bin/env python3
"""Guarded MySQL 8.4 M02 local writer bootstrap.

The generated password is captured only in process memory from a noninteractive
mysql client pipe. It is never placed in SQL input, argv, terminal output,
history, state, source, or evidence.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path("/opt/ops-drill-kit")
ADMIN_CNF = Path("/etc/opsdrill/mysql-admin.cnf")
WRITER_CNF = Path("/etc/opsdrill/mysql-m02-writer.cnf")
OPS_DIR = Path("/etc/opsdrill")

STATE_DIR = Path("/var/lib/opsdrill/m02-bootstrap")
STATE_FILE = STATE_DIR / "state.json"
LOCK_FILE = Path("/run/lock/opsdrill-m02-bootstrap.lock")

DB_USER = "orderguard_m02_writer"
DB_HOST = "localhost"
DB_NAME = "orderguard_stage3"
TABLE_NAME = "orders"

EXPECTED_IDS = (10086, 10087)
EXPECTED_STATUSES = {10086: 2, 10087: 3}

class SafeError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise SafeError(message)


def require_root() -> None:
    if os.geteuid() != 0:
        fail("必须以 root 执行")


def check_dir(path: Path, uid: int = 0, gid: int = 0,
              mode: int = 0o700) -> None:
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        fail("目录类型异常：" + str(path))
    if st.st_uid != uid or st.st_gid != gid:
        fail("目录所有者异常：" + str(path))
    if stat.S_IMODE(st.st_mode) != mode:
        fail("目录权限异常：" + str(path))


def check_regular(path: Path, uid: int = 0, gid: int = 0,
                  mode: int = 0o600, nlink: int = 1) -> os.stat_result:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        fail("文件不存在：" + str(path))
    if not stat.S_ISREG(st.st_mode):
        fail("目标不是普通文件：" + str(path))
    if st.st_uid != uid or st.st_gid != gid:
        fail("文件所有者异常：" + str(path))
    if stat.S_IMODE(st.st_mode) != mode or st.st_nlink != nlink:
        fail("文件权限或硬链接数异常：" + str(path))
    return st


def ensure_dirs() -> None:
    check_dir(OPS_DIR, 0, 0, 0o700)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_dir(STATE_DIR, 0, 0, 0o700)
    lock_dir = LOCK_FILE.parent
    st = os.stat(lock_dir)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
        fail("系统锁目录异常")


def acquire_lock() -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
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
        fail("另一个 M02 账号管理任务正在执行")
    return fd


def atomic_json(path: Path, data: Dict, replace: bool = False) -> None:
    if replace and os.path.lexists(path):
        check_regular(path)
    if not replace and os.path.lexists(path):
        fail("状态文件已存在，拒绝覆盖")
    fd, temp_name = tempfile.mkstemp(prefix=".m02-", suffix=".tmp",
                                     dir=str(path.parent))
    temp = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, 0, 0)
        payload = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temp, path)
        else:
            os.link(temp, path, follow_symlinks=False)
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def read_state() -> Dict:
    check_regular(STATE_FILE)
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        fail("状态文件无法解析，保留现场")
    if not isinstance(data, dict) or data.get("kind") != "m02-writer-bootstrap":
        fail("状态文件内容不符合契约")
    return data


def clear_state() -> None:
    if os.path.lexists(STATE_FILE):
        check_regular(STATE_FILE)
        STATE_FILE.unlink()
        dfd = os.open(STATE_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def mysql_command(cnf: Path, sql: str, timeout: int = 45) -> Tuple[int, str]:
    check_regular(cnf)
    argv = [
        "mysql",
        "--defaults-extra-file=" + str(cnf),
        "--batch",
        "--raw",
        "--skip-column-names",
        "--silent",
        "--skip-reconnect",
        "--default-character-set=utf8mb4",
    ]
    env = os.environ.copy()
    env["MYSQL_HISTFILE"] = "/dev/null"
    env.pop("MYSQL_PWD", None)  # Never inherit a password environment variable.
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            close_fds=True,
        )
        try:
            out, _ = proc.communicate(sql.encode("utf-8"), timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            return 124, out.decode("utf-8", errors="replace")
        return proc.returncode, out.decode("utf-8", errors="replace")
    except Exception:
        fail("MySQL 客户端启动或通信失败")


def mysql_admin(sql: str) -> str:
    rc, output = mysql_command(ADMIN_CNF, sql)
    if rc != 0:
        fail("管理员 MySQL 查询失败")
    return output.strip()


def global_snapshot() -> Dict[str, str]:
    output = mysql_admin("""
SELECT
 @@GLOBAL.server_uuid,
 @@GLOBAL.log_bin,
 @@GLOBAL.gtid_mode,
 @@GLOBAL.general_log,
 @@GLOBAL.slow_query_log,
 @@GLOBAL.log_output,
 @@GLOBAL.long_query_time,
 @@GLOBAL.socket;
""")
    values = output.split("\t")
    if len(values) != 8:
        fail("MySQL 全局状态读取异常")
    keys = ("server_uuid", "log_bin", "gtid_mode", "general_log",
            "slow_query_log", "log_output", "long_query_time", "socket")
    return dict(zip(keys, values))


def validate_globals(snapshot: Dict[str, str]) -> None:
    if snapshot["log_bin"] != "1":
        fail("GLOBAL log_bin 必须保持 ON")
    if snapshot["gtid_mode"].upper() != "OFF":
        fail("GTID_MODE 不是 OFF；拒绝制造未记录的 GTID 变更")
    if snapshot["general_log"] != "0":
        fail("general_log 必须为 OFF")
    if snapshot["slow_query_log"] != "0":
        fail("slow_query_log 必须为 OFF")
    if snapshot["log_output"] != "FILE":
        fail("log_output 与已验收基线不一致")
    if not snapshot["socket"].startswith("/"):
        fail("MySQL Unix Socket 路径异常")


def account_exists() -> bool:
    result = mysql_admin(
        "SELECT COUNT(*) FROM mysql.user "
        "WHERE User='orderguard_m02_writer' AND Host='localhost';"
    )
    if result not in ("0", "1"):
        fail("数据库账号存在性查询异常")
    return result == "1"


def sql_guard_prefix() -> str:
    # PREPARE/EXECUTE forces a server-side precondition gate on this connection.
    # The false branch deliberately references a nonexistent table; the mysql
    # client stops before any account DDL is sent.
    return r"""
SET @m02_guard_sql = IF(
    @@GLOBAL.log_bin = 1
    AND @@GLOBAL.gtid_mode = 'OFF'
    AND @@GLOBAL.general_log = 0
    AND @@GLOBAL.slow_query_log = 0
    AND @@SESSION.sql_log_bin = 1,
    'SET SESSION sql_log_bin = OFF',
    'SELECT * FROM `__M02_PRECONDITION_FAILED__`'
);
PREPARE m02_guard_stmt FROM @m02_guard_sql;
EXECUTE m02_guard_stmt;
DEALLOCATE PREPARE m02_guard_stmt;
SELECT CONCAT(
    'M02_SESSION_OFF|',
    @@SESSION.sql_log_bin, '|',
    @@GLOBAL.log_bin, '|',
    @@GLOBAL.gtid_mode
);
"""


def sql_guard_suffix() -> str:
    return r"""
SET SESSION sql_log_bin = ON;
SELECT CONCAT(
    'M02_SESSION_RESTORED|',
    @@SESSION.sql_log_bin, '|',
    @@GLOBAL.log_bin, '|',
    @@GLOBAL.gtid_mode
);
"""


def create_sql() -> str:
    return (
        sql_guard_prefix()
        + """
CREATE USER 'orderguard_m02_writer'@'localhost'
IDENTIFIED BY RANDOM PASSWORD;

GRANT
    SELECT (id, order_no, order_status),
    UPDATE (order_status)
ON `orderguard_stage3`.`orders`
TO 'orderguard_m02_writer'@'localhost';

"""
        + sql_guard_suffix()
    )


def rotate_and_grant_sql() -> str:
    return (
        sql_guard_prefix()
        + """
ALTER USER 'orderguard_m02_writer'@'localhost'
IDENTIFIED BY RANDOM PASSWORD;

GRANT
    SELECT (id, order_no, order_status),
    UPDATE (order_status)
ON `orderguard_stage3`.`orders`
TO 'orderguard_m02_writer'@'localhost';

"""
        + sql_guard_suffix()
    )


def grant_only_sql() -> str:
    return (
        sql_guard_prefix()
        + """
GRANT
    SELECT (id, order_no, order_status),
    UPDATE (order_status)
ON `orderguard_stage3`.`orders`
TO 'orderguard_m02_writer'@'localhost';

"""
        + sql_guard_suffix()
    )


def parse_random_password(output: str) -> Optional[str]:
    matches = []
    for line in output.splitlines():
        fields = line.split("\t")
        if (len(fields) == 4 and fields[0] == DB_USER
                and fields[1] == DB_HOST and fields[3] == "1"):
            matches.append(fields[2])
    if len(matches) != 1:
        return None
    password = matches[0]
    if (not password or any(ch in password for ch in "\x00\r\n\t")
            or len(password) < 5):
        fail("MySQL 返回的随机密码格式异常")
    return password


def option_quote(value: str) -> str:
    if any(ch in value for ch in "\x00\r\n\t"):
        fail("凭据包含不支持的控制字符")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_credential(password: str, socket_path: str,
                     replace_existing: bool = False) -> None:
    content = (
        "[client]\n"
        "user=orderguard_m02_writer\n"
        "password=" + option_quote(password) + "\n"
        "socket=" + option_quote(socket_path) + "\n"
        "database=orderguard_stage3\n"
        "protocol=SOCKET\n"
    ).encode("utf-8")

    if replace_existing:
        check_regular(WRITER_CNF)
    elif os.path.lexists(WRITER_CNF):
        fail("凭据文件已存在，拒绝覆盖")

    fd, temp_name = tempfile.mkstemp(prefix=".m02-credential-",
                                     dir=str(OPS_DIR))
    temp = Path(temp_name)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if replace_existing:
            os.replace(temp, WRITER_CNF)
        else:
            os.link(temp, WRITER_CNF, follow_symlinks=False)
        dfd = os.open(OPS_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
    check_regular(WRITER_CNF)


def writer_auth_ok() -> bool:
    if not os.path.lexists(WRITER_CNF):
        return False
    check_regular(WRITER_CNF)
    rc, output = mysql_command(
        WRITER_CNF,
        "SELECT CURRENT_USER(), DATABASE();",
        timeout=15,
    )
    return (
        rc == 0
        and output.strip()
        == "orderguard_m02_writer@localhost\torderguard_stage3"
    )


def grants() -> List[str]:
    output = mysql_admin(
        "SHOW GRANTS FOR 'orderguard_m02_writer'@'localhost';"
    )
    return [line.strip() for line in output.splitlines() if line.strip()]


def normalize_grant(line: str) -> str:
    return line.lower().replace("`", "").replace("'", "").replace('"', "")


def validate_grants() -> List[str]:
    lines = grants()
    normalized = [normalize_grant(line) for line in lines]
    if len(normalized) != 2:
        fail("账号权限条目数量不符合最小权限契约")
    usage = any(
        "grant usage on *.* to orderguard_m02_writer@localhost" in x
        for x in normalized
    )
    scoped = any(
        "grant select (id, order_no, order_status), update (order_status) "
        "on orderguard_stage3.orders to orderguard_m02_writer@localhost" in x
        for x in normalized
    )
    if not usage or not scoped:
        fail("SHOW GRANTS 与预期的列级权限不一致")
    return lines


def check_target_rows() -> None:
    output = mysql_admin("""
SELECT id, order_status
FROM orderguard_stage3.orders
WHERE id IN (10086, 10087)
ORDER BY id;
""")
    expected = ["10086\t2", "10087\t3"]
    if output.splitlines() != expected:
        fail("目标订单状态不符合已验证基线，拒绝初始化")


def save_state(snapshot: Dict[str, str], phase: str,
               replace_existing: bool = False) -> None:
    data = {
        "kind": "m02-writer-bootstrap",
        "account": DB_USER + "@localhost",
        "database": DB_NAME,
        "phase": phase,
        "server_uuid": snapshot["server_uuid"],
        "global_log_bin": snapshot["log_bin"],
        "gtid_mode": snapshot["gtid_mode"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "credential_path": str(WRITER_CNF),
        "contains_password": False,
    }
    atomic_json(STATE_FILE, data, replace=replace_existing)


def validate_session_markers(output: str) -> None:
    off = "M02_SESSION_OFF|0|1|OFF"
    restored = "M02_SESSION_RESTORED|1|1|OFF"
    if off not in output or restored not in output:
        fail("同一管理员会话的 sql_log_bin 关闭/恢复验证不完整")


def execute_account_sql(sql: str, rotate: bool = False) -> None:
    rc, output = mysql_command(ADMIN_CNF, sql, timeout=45)
    password = parse_random_password(output)

    # Persist the generated password even if a later GRANT/restore statement
    # failed. The state file remains, allowing recover to finish safely.
    if password is not None:
        snapshot = global_snapshot()
        if rotate and os.path.lexists(WRITER_CNF):
            write_credential(password, snapshot["socket"], True)
        elif not os.path.lexists(WRITER_CNF):
            write_credential(password, snapshot["socket"], False)
        else:
            fail("随机密码已生成但凭据文件已存在；保留现场")
        del password

    if rc != 0:
        fail("管理员 SQL 执行失败；保留状态，使用 recover 检查")
    validate_session_markers(output)


def verify_global_unchanged(expected_uuid: str) -> Dict[str, str]:
    after = global_snapshot()
    if after["server_uuid"] != expected_uuid:
        fail("MySQL server_uuid 发生变化")
    if after["log_bin"] != "1":
        fail("GLOBAL log_bin 未保持 ON")
    if after["gtid_mode"].upper() != "OFF":
        fail("GTID_MODE 发生变化")
    if after["general_log"] != "0" or after["slow_query_log"] != "0":
        fail("日志全局设置发生变化")
    return after


def remove_state_after_verify(snapshot: Dict[str, str]) -> None:
    if not account_exists():
        fail("账号不存在，不能清除状态")
    if not writer_auth_ok():
        fail("专用凭据认证失败，不能清除状态")
    validate_grants()
    verify_global_unchanged(snapshot["server_uuid"])
    clear_state()


def create_account() -> None:
    if os.path.lexists(STATE_FILE):
        fail("存在未完成初始化状态，先执行 recover")
    if account_exists():
        fail("数据库账号已存在，拒绝覆盖")
    if os.path.lexists(WRITER_CNF):
        fail("凭据文件已存在，拒绝覆盖")

    snapshot = global_snapshot()
    validate_globals(snapshot)
    check_target_rows()

    save_state(snapshot, "create-started")

    execute_account_sql(create_sql())

    if not os.path.lexists(WRITER_CNF):
        fail("账号创建结果未生成凭据文件，保留恢复状态")

    remove_state_after_verify(snapshot)

    print("PASS: M02 专用账号创建成功")
    print("PASS: sql_log_bin 在同一连接中 1 -> 0 -> 1")
    print("PASS: GLOBAL log_bin 始终为 ON")
    print("PASS: GTID_MODE 保持 OFF")
    print("PASS: 专用凭据认证成功")
    print("PASS: 列级权限符合契约")
    print("凭据文件：/etc/opsdrill/mysql-m02-writer.cnf")
    print("凭据内容未输出")


def status() -> int:
    pending = os.path.lexists(STATE_FILE)
    account = account_exists()
    credential = os.path.lexists(WRITER_CNF)
    print("pending_state:", "yes" if pending else "no")
    print("account_exists:", "yes" if account else "no")
    print("credential_file_exists:", "yes" if credential else "no")
    if pending:
        state = read_state()
        print("phase:", state.get("phase"))
        print("server_uuid_matches:",
              state.get("server_uuid") == global_snapshot()["server_uuid"])
        return 2
    if account and credential:
        return 0
    if not account and not credential:
        print("PASS: clean, no M02 writer account or credential")
        return 0
    print("STOP: account/credential state inconsistent; inspect before repair")
    return 2


def verify() -> None:
    if not account_exists():
        fail("M02 writer 账号不存在")
    if not writer_auth_ok():
        fail("M02 writer 凭据认证失败")
    lines = validate_grants()
    snap = global_snapshot()
    validate_globals(snap)
    print("PASS: writer authentication")
    print("PASS: exact least-privilege grants")
    print("PASS: GLOBAL log_bin=ON; GTID_MODE=OFF")
    for line in lines:
        print(line)


def recover(rotate: bool = False) -> None:
    if not os.path.lexists(STATE_FILE):
        fail("没有待恢复状态；不会自动修改账号或凭据")

    state = read_state()
    snapshot = global_snapshot()
    validate_globals(snapshot)

    if state.get("server_uuid") != snapshot["server_uuid"]:
        fail("MySQL server_uuid 与状态文件不一致，保留现场")

    exists = account_exists()
    credential_exists = os.path.lexists(WRITER_CNF)

    if not exists and not credential_exists:
        clear_state()
        print("PASS: 中断发生在账号创建前，已清除空状态")
        return

    if not exists and credential_exists:
        fail("凭据文件存在但账号不存在；保留文件和状态，禁止自动删除")

    if exists and credential_exists and writer_auth_ok() and not rotate:
        # Credential is usable. Re-apply only the intended grants with
        # binlogging disabled in this one admin connection.
        execute_account_sql(grant_only_sql())
    else:
        if credential_exists and not rotate:
            fail("凭据存在但认证失败；需要人工确认后显式执行 recover --rotate")
        execute_account_sql(rotate_and_grant_sql(), rotate=credential_exists)

    remove_state_after_verify(snapshot)

    print("PASS: M02 bootstrap recovery completed")
    print("PASS: credential authentication verified")
    print("PASS: exact column-level grants verified")
    print("PASS: global binlog remains ON")
    print("凭据内容未输出")


def dry_run() -> None:
    if os.path.lexists(STATE_FILE):
        fail("存在待恢复状态，dry-run 拒绝执行")
    if account_exists():
        fail("数据库账号已存在；dry-run 不执行覆盖")
    if os.path.lexists(WRITER_CNF):
        fail("凭据文件已存在；dry-run 不执行覆盖")
    check_target_rows()
    snapshot = global_snapshot()
    validate_globals(snapshot)

    # Same connection proves the current administrator can set this
    # restricted SESSION variable, and restores it before disconnect.
    sql = (
        sql_guard_prefix()
        + sql_guard_suffix()
    )
    rc, output = mysql_command(ADMIN_CNF, sql, timeout=20)
    if rc != 0:
        fail("管理员不具备 SESSION sql_log_bin 操作能力，或预检失败")
    validate_session_markers(output)
    after = global_snapshot()
    verify_global_unchanged(snapshot["server_uuid"])
    if after["log_bin"] != "1":
        fail("GLOBAL log_bin 发生变化")
    print("DRY-RUN PASS")
    print("PASS: same-session sql_log_bin 1 -> 0 -> 1")
    print("PASS: GLOBAL log_bin remains ON")
    print("PASS: GTID_MODE=OFF")
    print("PASS: general_log and slow_query_log remain OFF")
    print("No account or credential was created")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create", "status", "verify", "recover"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--rotate", action="store_true")
    args = parser.parse_args()

    require_root()
    ensure_dirs()
    lock_fd = acquire_lock()
    try:
        if args.action == "create":
            if args.rotate:
                fail("--rotate 仅用于 recover")
            if args.dry_run:
                dry_run()
            else:
                create_account()
        elif args.action == "status":
            if args.dry_run or args.rotate:
                fail("status 不接受附加参数")
            return status()
        elif args.action == "verify":
            if args.dry_run or args.rotate:
                fail("verify 不接受附加参数")
            verify()
        elif args.action == "recover":
            if args.dry_run:
                fail("recover 不支持 dry-run")
            recover(rotate=args.rotate)
        return 0
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SafeError as exc:
        print("FAIL:", str(exc), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("INTERRUPTED: state retained; run status/recover", file=sys.stderr)
        sys.exit(130)
    except Exception:
        # Never print subprocess output, SQL result sets, or third-party errors.
        print("FAIL: unexpected error; state retained; run status/recover",
              file=sys.stderr)
        sys.exit(1)
