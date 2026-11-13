# M03 独立真实 MySQL 生命周期候选

2026-11-13 在 VMware 恢复副本运行本目录同摘要候选：run `7204775d3659352e4a99e99a`，actor=agent。新建 socket-only source/target；8 个合成用户连接占满隔离 target，额外连接实际返回 MySQL 1040；释放后 Sleep=0、SELECT 1 成功；同一 run 的 reset 与重复 reset 返回 STOPPED。受保护证据位于 `/var/backups/opsdrill/M03/lifecycle-7204775d3659352e4a99e99a`。

之前一次依赖摘要笔误、一次默认内建 AUDIT cache cleaner 被过严拒绝，均保留失败记录；后者已对已知内建插件作精确例外，其他审计插件仍拒绝。测试账号使用公开合成标记，不是业务凭据。此候选不修改主库 max_connections，也不声称验证主业务链的 readiness；尚未接入统一 CLI。异常退出、磁盘限额、重启及所有阶段尚未全覆盖。身份不明时保留资源，禁止猜测清理。

`real_contract_candidate.py` 只适用于已审阅并安装到固定候选路径的授权实验机，会创建和停止两个隔离 MySQL 实例；失败保留状态。不要在生产或未知环境运行。
