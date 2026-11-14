# N02：隔离网络 ACL 故障排查

## 范围与前提

演练在授权 VMware 实验机的 `od-client`、`od-router`、`od-server` 网络命名空间内运行：注入在路由命名空间的受控 nftables 规则中丢弃发往 8080 的流量；3306 的临时监听器只是用于验证访问限制的 dummy TCP 服务，不是真实 MySQL。不要修改默认命名空间的防火墙或路由。

先检查项目根目录 README 的特权执行信任边界，确认无冲突的既有实验和资源。只有本人操作使用 `actor=user`；自动运行必须写 `actor=agent`。启动会实际注入故障，记录返回的 24 位 `run_id`：

```bash
sudo bin/opsdrill status
sudo bin/opsdrill start N02 --actor user
sudo bin/opsdrill check N02 --actor user --expect-run-id RUN_ID
```

确认本轮故障时 check 返回 1；环境、资源身份或权限异常不能当作故障判题通过。N02 check 会短时启动并核验本轮 dummy 监听器，其他时刻不保证服务端 8080 或 3306 持续监听。

## 定位

```bash
sudo ip -n od-client addr
sudo ip -n od-client route
sudo ip -n od-server route
sudo ip netns exec od-router nft -a list ruleset
sudo ip netns exec od-client ss -nt
```

先确认客户端的目标地址和网关、路由器两侧接口与转发，再检查本轮规则顺序和计数；必要时在客户端和服务端对应接口抓取 TCP 8080，在 check 运行的短窗口结合监听状态比较 SYN、SYN-ACK 和重传。只看到连接超时或没有 SYN-ACK 不能单独证明 ACL 是唯一原因；路由、服务未监听和回程路径也可能产生类似现象。抓包和日志可能包含敏感数据，分享前应限制范围并脱敏。

## 恢复与复位

用启动回执中的同一 `RUN_ID` 替换占位符。已安装的 root 控制器通过本轮身份检查后，只修复属于本轮的规则；此直接修复不会单独写 CLI 事件，随后用 CLI 检查和复位：

```bash
sudo /usr/bin/python3 -I -B /usr/local/libexec/opsdrill/n02/n02.py repair RUN_ID
sudo bin/opsdrill check N02 --actor user --expect-run-id RUN_ID
sudo bin/opsdrill reset N02 --actor user --expect-run-id RUN_ID
```

恢复检查同时验证本实验的 8080 可达与 3306 仍不可由客户端访问；最后 reset 清理核验过的本轮资源。控制器注册约 180 秒 watchdog 尝试恢复规则，但 watchdog 不替代最终 reset。未知规则、进程、命名空间，或提示状态损坏、注入中断、身份不明时，保留现场并核对，不能按名称批量 kill、flush 或删除。

## 已验证范围与参考

2026-11-12 在 Rocky Linux 恢复副本中由 `actor=agent` 完成过故障、修复、重复复位和 watchdog 验证；另一次对默认命名空间的网卡、地址、路由、nft 和部分网络参数作前中后摘要比较，记录及排除项见本目录 README。该结果不代表人工已练习，也不证明所有异常中断或跨重启恢复。

参考：[Linux network namespaces 手册](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)、[ip-netns 手册](https://man7.org/linux/man-pages/man8/ip-netns.8.html)、[Red Hat Enterprise Linux 9 防火墙与数据包过滤](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/epub/configuring_firewalls_and_packet_filters/configuring-destination-nat-using-nftables_configuring-nat-using-nftables)。
