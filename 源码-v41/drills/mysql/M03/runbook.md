# M03 连接耗尽

CLI 使用独立的 socket-only MySQL 双实例和合成账号，不修改主业务数据库的 `max_connections`。`opsdrill start M03 --actor agent` 输出 run ID；后续 `check`、`resolve`、`reset` 必须提供 `--expect-run-id`。正常故障判题要求实际 MySQL 1040；释放后还要确认 Sleep 为 0 且新连接成功。

在授权的隔离恢复副本上，`actor=agent` 的 run `026363941790aebb4af5c899` 已通过统一 CLI：8 个 Sleep、真实 1040、释放后 SELECT 成功、错误 run ID 拒绝、同轮两次 reset 成功。执行 `make contract-m03` 可在授权实验机新建一轮验证，结果保存在 `/var/backups/opsdrill/M03/` 下的独立目录。项目经历可结合真实记录说明，不编造手工操作和指标；该记录不证明主业务链 readiness 或所有异常恢复路径。

安装源码在 `experimental/m03/mysql-v1`，安装器为 `scripts/install_m03_mysql.py`；安装器要求自身及源码从 root 控制的安全目录执行，并校验固定摘要。不同版本、身份不明、启动中断或清理无法确认时保留状态和 run ID，按实际资源身份排查，不能猜测停止其他进程。看门时限不是跨重启或所有中断场景的完成证明。

## 官方参考

[MySQL 8.4：连接数耗尽](https://dev.mysql.com/doc/refman/8.4/en/too-many-connections.html)。

## 隔离应用就绪联动（2026-11-13，代理）

新机使用实际 FastAPI 就绪处理器和临时进程，在内存中将连接工厂指向本轮独立合成 MySQL。代理实测连接耗尽时 MySQL 返回 1040、隔离应用的 `/ready` 返回 503；释放连接后，同一应用进程与同一连接池的 `/ready` 返回 200。故障窗口工厂错误计数增加 1，恢复窗口无新增。CLI 同轮复位通过；已独立复核进程退出、事件均为 `actor=agent`、现有业务 readiness 为 200。结果位于 `/var/backups/opsdrill/M03/app-readiness-1c3373e7bbca236d/result.json`，SHA256 为 `5b32092ee6631cd1bf65ddae1570344a9f6a213ac55c19e2c9f159335aa3d206`。

`tests/contract/M03-app-readiness.py` 是这次通过实测的入口，配套 `m03-api-proxy.py` 和 `m03-api-probe-server.py`。三个文件须先随项目可信副本放在 root 控制、其他用户不可写的目录中，独立核对入口 SHA256 `2eee85117406bfb1c5b5caf95f2e1efd0f5cb578acc605d169a8d5914439e2fe` 和项目来源后，以 root 执行：

```bash
/usr/bin/python3 -I -B <可信项目副本>/tests/contract/M03-app-readiness.py \
  --vm-uuid <独立核实的目标VM-DMI-UUID> --source-root <可信项目副本>
```

入口要求目标机已有项目虚拟环境与 M03 控制器，验证固定版本应用源码、CLI、两个辅助文件的摘要以及受保护目录；异常状态或身份不符时拒绝，不能从普通用户可写目录以 root 执行。运行会创建本轮隔离 MySQL、只限 devops 用户连接的本地中继与临时应用进程；启动未确认时保留现场，不猜测清理。篡改辅助文件或使用错误 VM UUID 已验证会在创建 M03 事件前被拒绝。

这是实际应用处理器配合内存连接适配器与合成数据库的实验，不代表未改配置的主业务 API 曾连接故障库，不证明跨重启恢复或其他时间窗口的行为。
