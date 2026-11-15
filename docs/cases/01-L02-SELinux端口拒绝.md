# L02：SELinux 端口访问控制与服务恢复验证

## 验证摘要

独立 Nginx 绑 19081 起不来。切到 8443，同一个单元、同一条启动命令，起来了。全程 `Enforcing`，一条策略都没动。

## 环境与故障条件

- Rocky Linux 9.8，SELinux `Enforcing`，不关、不降级
- Nginx 跑在独立的 transient systemd 单元里，不碰系统自带的 `nginx.service`
- 服务运行上限 120 秒，独立 watchdog 约 180 秒后介入
- 实验机带 `/etc/opsdrill-lab` 标记，`systemd-detect-virt` 必须返回 `vmware`

## 第一次尝试

把端口写进配置，`systemctl start` 直接失败。

失败得很快——没有超时、没有 502、没有任何上游错误。这个"快"本身就是线索：说明进程卡在 `bind()` 阶段，还没进到 Nginx 自己的错误日志。

如果是防火墙丢包，现象会是连接超时；如果是配置写错，会先在 `nginx -t` 报出来。两种都不是，说明问题在更下层。

## 故障定位与排除项

按四条线走：

| 排查方向 | 验证方法 | 结果 |
|---|---|---|
| Nginx 配置语法错 | `nginx -t` | 通过，配置合法 |
| 端口被别的进程占了 | `ss -lntp` | 19081 空闲，无人监听 |
| 权限不够（非 root 绑低位端口） | 看单元身份 | 单元以 `httpd_t` 运行，不是裸进程 |
| 防火墙拦截 | 对照现象 | 拦截表现为超时，这里是立即失败 |

前三条排完，剩下 SELinux 和防火墙两条路。现象指向 SELinux，先查它。

## 定案

```bash
ausearch --input-logs -m AVC -ts recent
```

AVC 里出现 `denied { name_bind }`，`tclass=tcp_socket`。再查端口类型：

```bash
semanage port -l
```

19081 不在列表里。

结论：不是 Nginx 配错，是这个端口从来没被分配过 SELinux 类型。策略不知道它可以被谁使用，于是拒绝任何进程绑定。

**验收判定不是看一眼 AVC 就算。** 完整的拒绝需要三条审计记录同时对上：

```
type=AVC      ... denied { name_bind } for pid=<pid> scontext=...:httpd_t:s0 tclass=tcp_socket
type=SYSCALL  ... pid=<pid> success=no exe="/usr/sbin/nginx"
type=SOCKADDR ... saddr=<被拒绝的地址族与端口>
```

三行的 `pid` 必须相同，`exe` 必须指向同一个二进制。再加上同一 boot、同一 unit、同一 invocation 的日志时间窗。少任何一样，判 `PENDING`，不判通过。

这套关联防的是"看起来像"：日志里有 AVC 不等于这次启动被拒，也可能是上次的残留，或者别的进程干的。

## 处置方案与变更边界

两条路都能让服务起来：

1. `semanage port -a -t http_port_t -p tcp 19081` —— 给 19081 加一个类型
2. 换一个策略已放行的端口

采用第二条路径，将监听端口调整为当时空闲且策略允许的 8443。

**选择依据：保持验证环境策略基线一致。** 新增 SELinux 端口类型会留下持久配置变更，影响后续相同故障条件的可比性；调整监听端口不引入额外策略例外。

关闭 SELinux 会直接改变故障条件，因此不作为本次恢复方案。

本场景验证在 SELinux Enforcing 条件下完成端口拒绝定位与服务恢复。全程 `getenforce` 为 `Enforcing`，未修改 SELinux 策略。

## 验证

故障期：有 `name_bind` 拒绝、端口无监听。

恢复期：端口有监听、无新 AVC、HTTP 探测返回预期状态。

批次 `L02-20261113-670451`，四段事件记录各自留 SHA-256：注入、故障期检查、恢复检查、复位。

## 异常处置与工程改进

第一次跑（run `949c1b5837e9d7f934b51a26`）栽在时序上。

首次验证在 InvocationID 尚未落盘时注入异常，随后手动提前触发 watchdog，导致验收判定无法取得完整的 invocation 关联，证据链未闭合。

第二次（run `0ca533f01981bb1ec999bd7e`）改了两件事：

1. 不再手动提前调 watchdog，等满约 180 秒，由 systemd 定时器自然触发
2. watchdog 启动后先靠启动前写入受保护日志的随机标识认回本轮身份，再绑定 InvocationID，记录 `STOPPED_OR_ABSENT`

然后按同一 ID 复位，清理检查通过。链路闭合。

**多花三分钟，换来一条能自证的记录。** 手动调 watchdog 只能证明 watchdog 逻辑对，证明不了定时器接得对——这个区别值三分钟。

这也是 v2 控制器加"启动标识预写"的原因：InvocationID 是 systemd 启动后才有，中间有个窗口，窗口内崩溃就认不出身份。预写一个自己的标识，才能在窗口内也把身份认回来。

## 工程结论

**服务恢复状态必须与同一任务的证据关联。** 首次任务虽发生异常并完成处置，但 InvocationID 证据不完整，因此不计入完整闭环验证；后续通过启动身份预写与 watchdog 定时触发补齐关联条件。

## 验证范围

- 断电未测
- SIGKILL 未测
- 跨虚拟机重启未测
- `semanage` 写入实操没做（本案例刻意不做）
- 验收判定依赖 PID 与时钟关联，极端 PID 复用或时钟漂移理论上可能误判

状态不明时的处理是"保留现场、停止操作"，不批量删未知单元、不批量删 SELinux 规则。名字里带 `opsdrill` 不代表就是这一轮的。

## 验证入口

```bash
sudo bin/opsdrill start L02
sudo bin/opsdrill check L02 --expect-run-id RUN_ID
sudo bin/opsdrill reset L02 --expect-run-id RUN_ID
```

只在确认空闲、已授权的 VMware 实验机上跑。启动会真的注入故障。
