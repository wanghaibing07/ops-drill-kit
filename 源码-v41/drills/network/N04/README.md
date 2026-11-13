# N04：TIME_WAIT 与临时端口

演练在每轮独有的匿名 network namespace 中收窄临时端口范围，以回环短连接观察端口耗尽，不修改默认命名空间的端口范围。仅获得充分的故障证据才记录注入通过。

在已授权实验机内，以 root 调用 `bin/opsdrill start N04 --actor agent` 并保存输出的 run_id。随后使用同一 run_id 执行 `check N04 --expect-run-id ID --actor agent`、`resolve N04 --expect-run-id ID --actor agent`、`check`、`reset`。故障检查返回 1，恢复验证成功返回 0，证据不足或环境错误返回 2；其他 run_id 被拒绝。重复 reset 需要该轮受保护完成凭证。

2026-11-13 在隔离恢复副本实测 `make contract-n04`，run `116784566a17d25ef54b18cf`，actor=agent：检查到 32 个 TIME_WAIT；修复后单连接 8 次请求成功；同轮两次 reset、未知 run_id 拒绝及报告解析通过。该记录不是用户本人练习。

CLI 演练本身验证原生 TCP 连接复用；独立的 Nginx upstream keepalive 对照见下文。当前新版在启动控制器前记录 run_id；尚未创建或无法认证 identity 的中断仍可能需人工核查，禁止按名称或 PID 猜测清理。旧轮不明 socket 与 identity 必须保留；短生命周期不等于异常恢复全覆盖。

2026-11-13 另在匿名网络命名空间以独立 Nginx 与合成 HTTP 后端做对照：关闭 upstream keepalive 时 8 个请求使用 8 条后端连接；启用 HTTP/1.1、连接头清空与 upstream keepalive 后 8 个请求使用 1 条后端连接（后端连接编号直接观察）。run `a777a93a5a3675c9`，actor=agent，受保护证据 `/var/backups/opsdrill/N04/nginx-keepalive-a777a93a5a3675c9`。这是独立对照实验，尚未集成进 CLI 故障生命周期，也没有修改业务 Nginx。复现前审阅 `nginx_keepalive_probe.py`，仅在授权 VMware 实验机运行 `sudo unshare --net -- /usr/bin/python3 -B drills/network/N04/nginx_keepalive_probe.py`。

2026-11-13 已安装独立 recovery-v2 并保留旧版，正常 CLI 契约 run `495020af07059923461e3cc5` 通过，旧版 run `116784566a17d25ef54b18cf` 的完成凭证仍可重复验证。另一轮 `5938aec8b537a35ad92d7df8` 在 CLI 持久化 STARTING 身份后、接收控制器结果之前受控中断，使用该 ID 成功复位；actor=agent。该测试不覆盖所有中断时点，也不证明 namespace 不存在其他引用。新版第一次 reset 后若再次复位同一 ID，需要指定 `--n04-version recovery-v2`；旧版凭证仍走默认 legacy 路径。受控中断测试为 `tests/contract/N04-interrupt.py`，会真实操作实验资源，只在已授权空闲实验机运行。
