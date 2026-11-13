#!/usr/bin/env bash
set -Eeuo pipefail

DB="orderguard_stage3"
FILE="/var/tmp/ops-drill-kit/orders-1000-whole.tsv"
EXPECTED_SHA="14ac915c8ce2abd0e18ef22ea1bf7ee0ecb4b92de4c478e501c3d38aa851e6c8"

ADMIN_CNF="/etc/opsdrill/mysql-admin.cnf"

mysql_admin() {
    mysql \
        --defaults-extra-file="$ADMIN_CNF" \
        "$@"
}

# One privileged invocation keeps the protected MySQL config off argv and avoids
# repeated sudo prompts. The shared lab guard prevents use outside od-lab.
if [[ "$EUID" -ne 0 ]]; then
    echo "FAIL: 请通过 sudo 执行"
    exit 1
fi
# shellcheck source=/dev/null
source /opt/ops-drill-kit/lib/guard.sh
guard_require_lab
exec 9>/run/lock/opsdrill-stage3-import.lock
flock -n 9 || { echo "FAIL: another import is running"; exit 1; }

# =====================================================
# 1. 校验输入文件
# =====================================================

python3 - "$FILE" "$EXPECTED_SHA" <<'PY'
import csv
import hashlib
import os
import pwd
import stat
import sys

path = sys.argv[1]
expected_sha = sys.argv[2]

directory = os.path.dirname(path)
dir_info = os.lstat(directory)
info = os.lstat(path)

if not stat.S_ISDIR(dir_info.st_mode):
    sys.exit("FAIL: 数据目录不是普通目录")

expected_uid = pwd.getpwnam("devops").pw_uid
if dir_info.st_uid != expected_uid:
    sys.exit("FAIL: 数据目录所有者错误")

if stat.S_IMODE(dir_info.st_mode) != 0o700:
    sys.exit("FAIL: 数据目录权限不是 0700")

if not stat.S_ISREG(info.st_mode):
    sys.exit("FAIL: 数据文件不是普通文件")

if info.st_uid != expected_uid:
    sys.exit("FAIL: 数据文件所有者错误")

if stat.S_IMODE(info.st_mode) != 0o600:
    sys.exit("FAIL: 数据文件权限不是 0600")

if info.st_nlink != 1:
    sys.exit("FAIL: 数据文件硬链接数异常")

digest = hashlib.sha256()

with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        digest.update(chunk)

if digest.hexdigest() != expected_sha:
    sys.exit("FAIL: SHA256 不匹配")

rows = 0
special = 0
order_numbers = set()

with open(path, "r", newline="", encoding="utf-8") as f:
    reader = csv.reader(f, delimiter="\t")

    for row in reader:
        rows += 1

        if len(row) != 8:
            sys.exit("FAIL: TSV 字段数量异常")

        order_no = row[0]
        merchant_id = int(row[1])

        if order_no != f"OG{rows:012d}":
            sys.exit("FAIL: 订单号顺序异常")

        if order_no in order_numbers:
            sys.exit("FAIL: 订单号重复")

        order_numbers.add(order_no)

        if not 1 <= merchant_id <= 500:
            sys.exit("FAIL: 商户编号越界")

        if merchant_id == 88:
            special += 1

        if (rows % 20 == 0) != (merchant_id == 88):
            sys.exit("FAIL: 商户 88 分布异常")

        if not 1 <= int(row[2]) <= 50000:
            sys.exit("FAIL: 用户编号异常")

        if not 0 <= int(row[3]) <= 4:
            sys.exit("FAIL: 订单状态异常")

        if not 100 <= int(row[4]) <= 99900:
            sys.exit("FAIL: 金额异常")

        if row[5] not in ("card", "wallet", "bank"):
            sys.exit("FAIL: 支付渠道异常")

if rows != 1000 or special != 50:
    sys.exit("FAIL: 行数或商户 88 数量异常")

print("PASS: TSV 文件、SHA256、行数和业务字段检查通过")
PY

# =====================================================
# 2. 确认数据库处于可导入状态
# =====================================================

count=$(mysql_admin -Nse \
    "SELECT COUNT(*) FROM ${DB}.orders")

if [[ "$count" != "0" ]]; then
    echo "FAIL: 目标订单表非空，拒绝重复导入"
    exit 1
fi

merchants=$(mysql_admin -Nse \
    "SELECT COUNT(*) FROM ${DB}.merchants")

if [[ "$merchants" != "500" ]]; then
    echo "FAIL: 商户数量不是 500"
    exit 1
fi

old_count=$(mysql_admin -Nse \
    "SELECT COUNT(*) FROM orderguard.orders")

if [[ "$old_count" != "5" ]]; then
    echo "FAIL: 原业务订单数与基线不符"
    exit 1
fi

initial_state=$(mysql_admin -Nse \
    "SELECT @@GLOBAL.local_infile")

if [[ "$initial_state" != "0" ]]; then
    echo "FAIL: local_infile 初始状态不是 OFF"
    exit 1
fi

echo "PASS: 数据库导入前置检查通过"

# =====================================================
# 3. 注册退出清理函数
# =====================================================

cleanup() {
    local rc=$?

    trap - EXIT INT TERM HUP
    set +e

    echo "恢复 local_infile=OFF ..."

    mysql_admin -e \
        "SET GLOBAL local_infile=OFF" >/dev/null

    local restore_rc=$?

    local state
    state=$(mysql_admin -Nse \
        "SELECT @@GLOBAL.local_infile")
    local verify_rc=$?

    if [[ "$restore_rc" -ne 0 ||
          "$verify_rc" -ne 0 ||
          "$state" != "0" ]]; then
        echo "FAIL: 无法确认 local_infile 已关闭"
        exit 1
    fi

    echo "PASS: local_infile=OFF"

    exit "$rc"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# =====================================================
# 4. 临时开启 LOCAL 导入能力
# =====================================================

mysql_admin -e \
    "SET GLOBAL local_infile=ON"

echo "开始导入 1000 条合成订单 ..."

# =====================================================
# 5. 导入并检测 MySQL 警告
# =====================================================

warnings=$(mysql_admin \
    --local-infile=1 \
    --batch --skip-column-names \
    "$DB" -e "
LOAD DATA LOCAL INFILE '$FILE'
INTO TABLE orders
CHARACTER SET utf8mb4
FIELDS TERMINATED BY '\t'
LINES TERMINATED BY '\n'
(
    order_no,
    merchant_id,
    user_id,
    order_status,
    amount_cents,
    pay_channel,
    created_at,
    updated_at
);

SELECT @@warning_count;
")

if [[ "$warnings" != "0" ]]; then
    echo "FAIL: 导入存在 MySQL 警告，数量：$warnings"
    echo "保留影子库当前状态，禁止自动重试"
    exit 1
fi

# =====================================================
# 6. 校验数据库记录
# =====================================================

result=$(mysql_admin -Nse "
SELECT CONCAT(
    COUNT(*), ',',
    SUM(merchant_id = 88), ',',
    COUNT(DISTINCT order_no)
)
FROM ${DB}.orders;
")

if [[ "$result" != "1000,50,1000" ]]; then
    echo "FAIL: 数据库数量校验不通过：$result"
    exit 1
fi

echo "PASS: 1000 条订单导入成功"
echo "PASS: 商户 88 恰好 50 条"
echo "PASS: 1000 个唯一订单号"

# 退出时自动调用 cleanup
