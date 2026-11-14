# M04 历史证据核对

下面的命令只读取此前一次自动执行的备份和恢复证据；不会连接 MySQL、回放事务或改变实验环境：

```bash
sudo python3 scripts/verify_m04_evidence.py \
  /var/backups/opsdrill/M04/formal-20261112-02 \
  /var/backups/opsdrill/M04/full-20261111-01/database.restore.sql.gz
```

该工具核对备份摘要、连续的 binlog 文件和回放文件摘要、记录的事务位置与恢复和清理结果的一致性。`CONSISTENT` 只说明当前文件与这些记录相符，并不重新执行恢复、独立审计 SQL 语义、验证当前数据库。证据目录和备份在同一虚拟磁盘上，不构成异机灾备。

历史记录包含服务重启时 `binlog.000008` 截断至 158 字节的事实；证据目录中的审计结果保留了这一说明。不要用该工具的通过结果掩盖这个事实。M04 的自动注入、判题、复位及完整应用恢复仍需另行完成和验收。

## 2026-11-12 隔离 PITR 与应用文件实验

在 VMware 恢复副本中，两个专用 socket、禁止网络访问的临时 MySQL 实例分别承担源库和恢复库。将上述历史备份导入源库后，重新生成全备，在源库执行一次合成订单金额更新和一次受控删除，再把全备恢复到第二个实例并回放删除前的 binlog。

本次恢复结果为 500,000 条订单、商户 88 的 25,000 条订单；金额更新保留，受控删除的订单仍存在。除被故意删除的一行外，源库与恢复库全部订单字段按 ID 排序后的 SHA-256 相同。日志文件的事件 CRC 校验通过：起点为 158，更新事务结束及删除事务开始位置为 586，删除事务结束位置为 948。该结论仅针对本次独立实例新生成的备份和日志，不证明历史 binlog 连续性、异机容灾或所有其他表的业务语义。

受 root 保护的原始文件、摘要、结果及独立核对结果保存在恢复副本的 `/var/backups/opsdrill/M04/isolated-pitr-09fb97a9d58e7ae4/`。两个临时实例已停止；单次演练脚本仍有异常回收、超时和权限收敛等待完善，不能作为正式控制器。

随后另建两个独立临时实例，以两条合成订单和非秘密一次性测试标记验证受限回放：目标账号仅有 `REPLICATION_APPLIER` 与订单表 `UPDATE` 权限，经审计的密封内存流成功回放更新；删除订单和更新其他表均被拒绝，账号清理后两个实例已停止。初始化日志和服务日志中未发现测试标记，主库 UUID、订单数和金额总和前后一致。结果位于 `/var/backups/opsdrill/M04/restricted-replay-probe-8ed4b0bcb9e98246/probe-result.json`。首次探针因检测到审计类插件安全拒绝；后续仅对非秘密实验明确允许两个 MySQL 内置认证缓存清理插件。该实验不证明其他日志渠道不会记录口令，也没有启用正式业务回放入口。

MySQL 官方文档分别说明 [`sha2_cache_cleaner`](https://dev.mysql.com/doc/refman/8.4/en/caching-sha2-pluggable-authentication.html) 和 [`mysqlx_cache_cleaner`](https://dev.mysql.com/doc/refman/8.4/en/x-plugin-sha2-cache-plugin.html) 用于维护认证缓存；插件用途说明本身不能代替对其他日志渠道的核查。

另对 5 个明确选定的非秘密应用源码、依赖清单和服务文件进行了隔离备份与恢复，核对文件内容 SHA-256 和普通权限位；当前工具版本的实机证据位于 `/var/backups/opsdrill/M04/app-files-eef9327854239df3/`。此实验未验证所有权、ACL、扩展属性、SELinux 标签、上传文件、应用启动或应用与数据库恢复点的一致性。

`scripts/app_backup.py` 可在受信任、没有恶意并发写入者的独立实验目录里，按显式清单备份和恢复普通文件。实验根目录必须有内容为 `ops-drill-kit` 的 `.opsdrill-lab`，目标父目录应事先存在，而每次的目标目录必须不存在：

```bash
python3 scripts/app_backup.py backup --lab /path/to/lab --source source --dest backups/run1 --file app/main.py
python3 scripts/app_backup.py restore --lab /path/to/lab --backup backups/run1 --dest restores/run1
```

该工具复制内容和普通权限位，不恢复所有者、ACL、扩展属性或安全标签，也不提供并发攻击防护。它不直接替换运行中的应用文件；生产部署、密钥或未知目录不在本实验范围内。

2026-11-12 又在隔离恢复副本中使用两条合成订单验证了更新后的候选代码：探针通过真实 `replay_account` 上下文生成非秘密临时凭据，调用 `account.apply` 消费密封回放流；更新生效，删除订单及跨表更新被拒绝，账号清理记录消失，两个临时实例停止。主库 UUID、订单数量和金额合计前后一致。`init.log`、`server.log` 未发现本轮非秘密测试标记，其他日志渠道及真实口令暴露风险仍未得到完整证明。此次使用的测试身份检查仅为内置认证缓存清理插件放行；正式账号和业务入口仍默认禁用。结果和校验清单位于 `/var/backups/opsdrill/M04/restricted-replay-probe-035d1f1f42292e92/`。这是一次小规模集成测试，不是完整 M04 自动演练，也不计入人工演练。

## 合成数据自动恢复候选（2026-11-13）

在隔离恢复副本中，run `d9c125e7ea45399d` 实际执行固定合成表的全备、目标实例导入、先更新再误删、按 binlog 位置回放并校验全部字段，最终两个临时实例停止。备份起点和结束为 `pitr-bin.000002:158`，回放截止 `584`，删除后位置 `945`。状态和文件保存在 `/var/tmp/opsdrill-m04-controller/d9c125e7ea45399d/`；本轮运行的保护副本和结果摘要保存在 `/var/backups/opsdrill/M04/synthetic-candidate-20261113/`。主业务服务在演练后仍为 active，但本轮没有读取或比较主库数据。

源码及离线测试位于 `experimental/m04/continuation`；`make test-m04-synthetic` 只运行模拟测试。该候选仅执行全新 socket-only 实例和固定合成数据，正式业务回放仍关闭。正常链路的一次通过不等于统一 CLI、跨进程 reset、异常与重启恢复、磁盘总配额或应用与数据库联合恢复已通过。项目经历可结合真实记录描述，不编造手工操作和指标。

当前运行入口只适合授权的隔离实验机：应先审阅并将候选与依赖逐字节暂存至 root 控制目录，运行该受保护副本；不应从普通用户可改写目录以 root 直接执行。若中断或状态不明，保留 run ID、日志和实例，按身份核实，不按名称猜测清理。

2026-11-13 分命令候选实测：run `4ca9da691ee8f1fb` 依次得到 FAULT、FAULT、RECOVERED、RECOVERED、STOPPED、STOPPED；每一步由独立进程完成。首次尝试 `d4d23b83adf288d2` 因启动时内存中的身份参数为元组而被校验拒绝；修复后回归测试通过，首次尝试的两个实例经身份核验已停止。记录位于 `/var/backups/opsdrill/M04/synthetic-candidate-20261113/` 和各轮受保护状态目录。本结果不代表统一 CLI、异常重启或磁盘总配额已完成。
