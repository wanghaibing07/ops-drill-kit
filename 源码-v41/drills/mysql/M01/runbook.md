# M01 Runbook

## 安全边界

只在通过 `lib/guard.sh::guard_require_lab` 与 `systemd-detect-virt=vmware` 的实验虚拟机执行。仅变更 `orderguard_stage3.orders.idx_merchant_status_created` 的 VISIBLE 属性。

`inject.sh`、`reset.sh`、`solution.sh` 为变更命令；需要 `sudo`。`check.sh` 只读查询数据库（会为协调运行获取本地文件锁），不修改表或全局 MySQL 参数。所有动作使用同一 `/var/lib/opsdrill/m01/m01.lock`。

统一 CLI 的运行 ID、定时恢复与专属解法见 `README-owned.md`；下面保留独立入口的操作方式。两种入口不能同时接管同一轮。

## 操作

```bash
sudo bash drills/mysql/M01/check.sh
sudo bash drills/mysql/M01/inject.sh --dry-run
sudo bash drills/mysql/M01/inject.sh
sudo bash drills/mysql/M01/check.sh  # 退出 1，故障存在
sudo bash tests/solutions/M01/solution.sh
sudo bash drills/mysql/M01/check.sh  # 退出 0
sudo bash drills/mysql/M01/reset.sh
sudo bash drills/mysql/M01/reset.sh # 幂等
```

不在注入期间运行 M01 的 50 次性能基准；若要比较，单独通过读权限进行并记录 SQL、计划与原始样本。

## 恢复和异常

若注入过程遭 SIGKILL 或 VM 崩溃，先检查 `/var/lib/opsdrill/m01/state.json`、当前索引身份和可见性；统一 CLI 持有的轮次按 `README-owned.md` 使用同一 run ID。身份不明时保留现场，不能盲目运行旧版独立 reset。重启后的保守复位仅有模拟测试，尚未通过真实 VM 重启验证；确认恢复后再核对索引 VISIBLE 和固定 EXPLAIN。

本演练不修改 `slow_query_log`、`long_query_time`、`log_output`、`log_queries_not_using_indexes`、`local_infile`。注入前记录其全局值，复位时比对。如果发生外部配置漂移，仅报告且不擅自改回，因为无法判断是谁修改以及持久化配置源为何。必要时由管理员审查 `SHOW GLOBAL VARIABLES`、`/etc/my.cnf.d/`、`SET PERSIST` 状态后单独执行恢复变更。

故障注入使用 DDL，非事务型回滚；进程异常时以独立查询检查最终状态，不能假设 DDL 未生效。外部数据库管理员不受本地 flock 限制，需按维护窗口隔离非合作 DDL。

## 官方参考

[MySQL 8.4：不可见索引](https://dev.mysql.com/doc/refman/8.4/en/invisible-indexes.html)。
