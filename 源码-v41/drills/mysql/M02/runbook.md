# M02 操作入口

此目录通过 `scripts/m02_deadlock.sh` 转发到独立安装的 root 控制器。该控制器实施 VMware 护栏、互斥锁和 M02-B 死锁演练。现场前置条件和异常恢复见 `docs/runbooks/M02-row-lock-deadlock.md`。

普通用户信任项目文件后可运行 `bash drills/mysql/M02/inject.sh`、`check.sh` 和 `reset.sh`；不要用 sudo 执行项目内可写 wrapper。root 直接调用 `/usr/bin/python3.11 -I -S -B /usr/local/libexec/opsdrill/m02/m02_launcher.py`。部署及 sudo 授权须单独审阅。

统一 CLI 执行 `start M02` 时先持久化并输出 run ID；之后使用 `check M02 --expect-run-id <ID>`、`reset M02 --expect-run-id <ID>`。每次 check 验证本轮 1213 证据和当前恢复状态；故障在启动阶段已回滚，并非持续注入。reset 验证恢复后保留 root 状态中的完成记录，因而同一轮可以继续 check 和重复 reset。未匹配的 ID、缺失状态或归属不明时拒绝推断。启动新一轮会替换上一轮的完成记录；之后不能再以旧 ID 检查或重复 reset。无归属 wrapper 不能覆盖 CLI 所有的完成记录。

中断发生在底层状态写入前，或与旧版控制器混用时，可能无法自动恢复；先由操作人核查，不得删除未知状态或用其他 ID 代替。个人复盘和计时由练习者填写。

## 统一 CLI 实机验证

在授权的恢复副本，run `c8c02dc14c1143d26f770ee9` 真实触发 MySQL 1213，验证错误 ID 拒绝、check、reset、reset 后 check 和同 ID 重复 reset。受保护的结果摘要位于 `/var/backups/opsdrill/M02/cli-integration-20261113/contract-results.json`；真实故障证据由控制器生成，未计作人工操作。`make contract-m02` 会在授权的实验机上运行新一轮并创建独立结果目录。仅保留最新的底层完成状态：新一轮成功后不能再用旧 ID 重复 check/reset，历史证据文件仍保留。

## 官方参考

[MySQL 8.4：InnoDB 死锁](https://dev.mysql.com/doc/refman/8.4/en/innodb-deadlocks.html)、[事务和锁等待信息](https://dev.mysql.com/doc/refman/8.4/en/innodb-information-schema-transactions.html)。

## 固定种子基线的版本隔离（2026-11-13）

旧运行时的 10086/10087 状态严格为 3/3，保留用于历史环境；独立 `baseline-v2` 运行时严格要求新机固定种子的 2/3。新机的 v2 控制器和专用写账号已安装，认证及精确授权通过，配置前后订单状态保持 2/3。新机选择 `--m02-version baseline-v2`；有 CLI 状态时后续 check/reset 自动沿用该版本，状态复位后的重复 check/reset 需再次显式提供版本。无版本参数保持旧运行时行为。

新机隔离夹具 run `5e5098fa2e31d07f` 实际调用 v2 控制器触发 MySQL 1213、检查和两次复位；结果与证据摘要已核验，临时实例停止、夹具凭据清理，业务目标行仍为 2/3。结果位于 `/var/tmp/opsdrill-m04-controller/5e5098fa2e31d07f/m02-fixture-result.json`。这是隔离夹具直接调用控制器的验证，不是正常统一 CLI 的端到端契约。自动演练使用 `actor=agent`，不是本人练习。


隔离 CLI 快照 run `f8e4e46a10396dbc` 使用为隔离夹具适配路径及摘要清单的 CLI、launcher 和 v2 控制器，验证启动、检查、复位、重复检查与复位，错误 run ID 被拒绝。独立复核死锁证据摘要、4 条 `actor=agent` 事件、临时实例停止及夹具凭据删除，业务 readiness 为 200。结果在 `/var/tmp/opsdrill-m04-controller/f8e4e46a10396dbc/m02-fixture-result.json`。这不等于新机未修改的普通 CLI 完整实机契约通过。


新机另一次run `96d88e2a43d1d6fb` 使用与交付包相同摘要的原样 CLI 和已安装的原样 v2 控制器，在私有挂载命名空间映射隔离配置、状态及证据目录，连接独立 socket-only 合成数据库。启动、检查、复位、重复检查和复位通过，错误 ID 被拒绝；死锁证据摘要、4 条事件、实例停机和临时凭据删除均独立复核。结果在 `/var/tmp/opsdrill-m04-controller/96d88e2a43d1d6fb/m02-fixture-result.json`。该测试不代表普通宿主机配置的完整端到端契约。事件记录仅有 attempt ID；run ID 与版本保存在独立运行结果及状态证据中，不能声称事件自身包含完整关联。此前 run `d2334722d6b1db63` 因隔离状态目录缺失在注入前失败，保留失败账本，并使用独立受控续接记录完成临时资源清理。

新建空盘 VM 的普通配置使用 `baseline-v2` 在run `6ef54f78ad4df1beff8b247b` 通过统一 CLI 的真实死锁、检查、复位和重复检查/复位；错误 ID 被拒绝。首次 run `9db4866feadcd8f467485490` 因控制器状态目录缺失，在获取锁和连接数据库之前失败，原 CLI 状态及失败事件已保留；核对目标固定行和活动事务后补建目录，再受控续接。新版 bootstrap 在安装阶段安全创建 M02 状态与证据目录，已有不安全目录将被拒绝，不改写。两轮均为 `actor=agent`，不计入人工演练。
