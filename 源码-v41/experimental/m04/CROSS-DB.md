# M04：跨 Schema 同事务 PITR 验证

2026-11-13 的本轮实验 `d4f958b238ae8156` 在两台隔离、仅使用本地 socket 的 MySQL 实例上完成。一个一致性逻辑备份包含两个小型合成 Schema；源实例在同一连接、同一事务中分别更新两个 Schema，随后以独立事务删除一行。目标从共同备份恢复后，回放到提交之后、删除之前；两表的完整行和结构摘要与删除前状态一致。

证据位于实验机 `/var/tmp/opsdrill-m04-controller/d4f958b238ae8156/`，其中含 `synthetic-backup.sql`、状态和 `cross-db-result.json`；对应 Binlog 保存在该运行的隔离 source 数据目录。账本绑定备份、Binlog 和实际审计器摘要。验证坐标为同一文件 `pitr-bin.000002` 的 158 → 566 → 846；源与目标 UUID 和 server_id 各不相同。两个实例均已按身份停止。不要提交或公开备份、Binlog、凭据或原始日志。

该实验使用 GTID OFF，恢复和回放使用隔离目标上的 root。它不是跨实例分布式事务、GTID 恢复、生产备份或完整业务 M04 CLI 契约。较早的 `774dc866d185cd0c` 首次审计拒绝后通过独立账本受控续接；旧失败状态保留，其 dump 未持久化，不能将两次实验混作同一次无干预通过。

`cross_db_audit.py` 是针对两张固定合成表和一个 Binlog 文件的窄范围审计器，不支持任意 Schema 或数据类型。它检查事务边界、CRC、表映射和行镜像；`tests/python/test_cross_db_audit.py` 检查正确事务和错误提交边界。`cross_db_pitr_probe.py` 只用于授权实验 VM，需要先在 root 控制的目录中独立核对代码及其 14 项 v3 运行时清单与审计器摘要，并按脚本中固定的 root 保护位置暂存审计器。显式传入 `--apply --actor agent` 才会创建新的隔离实例；失败保留现场，须按记录的身份检查，不要盲目重试或清理。
