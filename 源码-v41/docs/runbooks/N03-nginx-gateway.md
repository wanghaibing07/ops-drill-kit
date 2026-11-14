# N03：Nginx 502 与 504（进行中）

本项目为单台隔离虚拟机内的模拟业务，Nginx 在 `127.0.0.1:8080` 反向代理 `127.0.0.1:8000`。502 和 504 模式的正常流程已在实验机验证；故障和中断范围以 `drills/network/N03/runbook.md` 的最新记录为准。

## 现象和判断

- 502 表示网关未能得到有效的上游响应；连接拒绝是可能原因之一，但状态码本身不足以证明后端进程宕机。
- 504 表示网关等待上游响应超时；不能单凭状态码认定数据库慢。`proxy_read_timeout` 限制两次连续读取之间的间隔，并非整个请求的绝对时长。
- 分别检查 Nginx、API 的服务状态、监听端口和错误日志，并用响应状态确认影响范围。日志可能含请求信息，分享前先脱敏。

## 受控慢请求

`/api/v1/orders/slow` 默认关闭；实验 VM 使用 `conf/40-opsdrill-n03.conf` 允许演练，但只有本轮受保护的开关有效时才接受慢请求，否则返回 404。有效开关受启动周期和单调时钟约束，最多有效 120 秒；Linux 系统挂起时间不计入该时钟，VM 暂停和恢复的行为尚未实测。接口固定等待 12 秒，单进程最多同时处理一个慢请求，其余慢请求返回 429；正常健康请求不需要等待该慢请求。本机 Nginx 当前读取超时为 10 秒。已经开始处理的慢请求可能在开关关闭后继续到其 12 秒等待结束。

```bash
curl --max-time 15 -i http://127.0.0.1:8080/api/v1/orders/slow
curl --max-time 3 -i http://127.0.0.1:8080/health
curl --max-time 5 -i http://127.0.0.1:8080/ready
sudo systemctl status nginx orderguard-api --no-pager
sudo ss -lntp
```

实验中真实链路的慢请求返回了 504，随后 `/health` 和 `/ready` 返回 200；这是项目的真实自动执行结果，执行者标记为 auto，可用于项目复盘和展示。

## 502 受控实验

仅在本项目 VMware 实验机运行。执行前确认业务健康；注入会短暂停止 `orderguard-api`，使 Nginx 返回 502：

```bash
sudo bin/opsdrill start N03 --variant 502
sudo bin/opsdrill check N03
sudo bin/opsdrill reset N03
```

控制器先创建并核对独立的 systemd 恢复看门狗，默认约 120 秒后检查并在身份符合条件时恢复服务。`check` 在故障存在时返回 1，服务恢复且 `/health`、`/ready` 正常时返回 0；`reset` 可重复执行。控制器意外终止后的自动恢复已用 8 秒测试副本实测，正式超时仍为 120 秒。看门狗会在服务配置发生变化或身份不明确时拒绝重启，需人工检查；虚拟机重启后的恢复尚未验证。

## 504 受控实验

仅在本项目 VMware 实验机运行。启动时控制器先确认看门狗已就绪，再创建与本轮运行 ID 绑定的开关，并通过真实网关请求验证 504。启动输出包含 `run_id`；保留它用于本轮修复。

```bash
sudo bin/opsdrill start N03 --variant 504
sudo bin/opsdrill check N03
sudo /usr/bin/python3 -I -B /usr/local/libexec/opsdrill/n03/n03_502.py resolve RUN_ID
sudo bin/opsdrill check N03
sudo bin/opsdrill reset N03
```

将 `RUN_ID` 替换为启动输出中的本轮值。`check` 在开关有效时报告开关仍然开启，不会重复发起长请求，也不声称刚刚观察到新的 504；启动阶段已验证过真实 504。已安装的 root 控制器直接执行 `resolve`，它只关闭对应运行的开关，保留演练状态供 `check` 判题；直接调用不会写 CLI 事件。`reset` 再清理状态和本轮定时器。看门狗或手动 reset 会删除开关；即使定时器失效，应用也会在开关到期后拒绝新的慢请求，但遗留文件和状态仍需检查、复位。中断后看门狗恢复和停止定时器后的过期测试，分别使用 8 秒和 6 秒测试副本；正式看门狗和应用端最长有效期均为 120 秒。自动执行记录可用于项目复盘和展示，执行者标记保持真实。虚拟机重启后的完整恢复流程尚未实测。

原有 access log 保留；单独的 `/var/log/nginx/orderguard-timing.log` 记录请求 ID、方法、状态、`request_time`、`upstream_connect_time` 和 `upstream_response_time`。响应头中的 `X-Request-ID` 可与该文件关联；该文件不记录 URL、查询参数或客户端地址。`request_time` 是 Nginx 对整个请求的计时，`upstream_response_time` 是上游响应时间，不应把两者差值直接称为公网延迟。

参考：[Nginx proxy 模块](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)、[Nginx 日志](https://docs.nginx.com/nginx/admin-guide/monitoring/logging/)。
