# N01 DNS 解析故障

在隔离命名空间中使用错误 DNS 记录，直接 IP 仍可访问。通过 `opsdrill start N01` 获取 run ID；`check`、`resolve`、`reset` 使用 `--expect-run-id`。修复后核验 DNS、getent 和域名 HTTP。项目经历可结合真实记录说明；实际由自动执行的操作应如实标记，不编造手工操作和指标。

新安装时，先将安装器和两份源码复制到 root 控制且祖先目录均不允许普通用户写入的暂存目录，独立核对 SHA256：安装器 `cc29581c0782712179064416e63d195f22543fec60be6af2ade8b25a30e5b495`、`n01.py` `954c3bc7f4e4c59156d7ae612ae107de76ee21204cf8333ce989a721cd5cc8a8`、`n01_watchdog.py` `183545f5421be32e41281be0ca340fe248436095902bf2b6969fce287c4976be`。确认后从该目录执行 `sudo python3 -I -B <受保护目录>/install_n01.py <受保护目录>/n01.py <受保护目录>/n01_watchdog.py`；不要直接以 root 执行普通用户可写的项目文件。安装器的自检不能证明它运行前未被修改。安装器要求 VMware 实验机标记、root 控制的目标目录，已安装相同版本时可重复运行；遇到旧版、未知文件或不安全路径时拒绝覆盖。旧版迁移需单独审查，不把安装当作升级。

在隔离恢复副本通过 CLI 常规演练（run `6f06f99e1a43f51c932ae676`）；另一次真实中断 supervisor 后，systemd 定时恢复返回 success，生成清理凭据，同一 run 连续两次 reset 成功（`253017f54d68ae7950916e2b`）。这只证明该次中断场景，不代表所有异常都能自动恢复。

看门狗记录在 `/run`，不跨重启。记录或定时器建立前中断、锁争用、资源身份不明、进程仍存活或规则漂移等情况可能拒绝清理，需保留现场并核查本轮身份；不得按名称批量删除。仅在授权实验 VM 使用。

## 官方参考

[Linux network namespaces 手册](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)、[resolv.conf 手册](https://man7.org/linux/man-pages/man5/resolv.conf.5.html)。
