# N02：隔离网络 ACL 排障

本演练在独立 network namespace 中创建 client、router 和 server；只在 router 中插入一条针对 8080 的 DROP 规则，不修改默认 namespace 的路由或防火墙。测试用的 3306 监听器是临时 dummy 服务，不是 MySQL。

控制器必须经 `scripts/install_n02.py` 安装到 root 控制的固定路径。每轮有随机 run ID 和 180 秒 watchdog；watchdog 只尝试恢复规则，演练仍须使用 `reset` 删除本轮资源。watchdog 锁争用最多等待 30 秒，身份不明或其他异常时拒绝操作；它不能保证跨重启恢复。若状态或规则不匹配，不要手动批量删除未知资源。

2026-11-12，Rocky Linux 隔离恢复副本上验证了控制器注入、故障判定、修复、重复复位和 180 秒 watchdog 恢复。默认 namespace 的 IPv4 路由和 nft 规则在测试前后相同。这是本项目的实操记录，覆盖注入、定位、恢复、判题四段。

同日另一次 ，在注入前、故障期间和复位后对默认 namespace 的网卡、IP 地址、IPv4/IPv6 路由、nft 规则以及选定网络 sysctl 做快照摘要比较，均一致；比较排除了会随时间变化的计数器和过期时间。结果位于恢复副本的 `/var/backups/opsdrill/network-verification-fa3959f8c83831e5/N02.json`。此检查不代表覆盖全部网络配置，也不证明异常中断和重启后的恢复。