# Runbook N03：Nginx 502 与 504

## 范围和前提

仅在带 `/etc/opsdrill-lab` 标记的项目虚拟机上使用。502 变体暂时停止实验订单 API；504 变体只启用本轮受控慢接口。注入前确认没有其他 N03 活动，保存 `start` 回执中的 `run_id`。不要关闭 SELinux，或修改无关服务、快照、历史日志。

```bash
sudo bin/opsdrill status
sudo bin/opsdrill start N03 --variant 502 --actor user
# 或：sudo bin/opsdrill start N03 --variant 504 --actor user
sudo bin/opsdrill check N03 --actor user --expect-run-id RUN_ID
```

只有用户亲自操作时才用 `actor=user`；自动测试使用 `actor=agent`。有效故障的 check 返回 1，环境或状态不符返回 2。没有活动演练时 check 不代表通过。

## 最初排查

```bash
curl -i --max-time 5 http://127.0.0.1:8080/health
systemctl status nginx orderguard-api --no-pager
ss -lntp | grep -E ':(8000|8080)\b'
sudo journalctl -u orderguard-api -b --no-pager -n 50
sudo tail -n 50 /var/log/nginx/orderguard-error.log
```

502 场景可观察连接上游失败；504 场景通过 `http://127.0.0.1:8080/api/v1/orders/slow` 触发受控慢请求，Nginx 可能记录 upstream timeout。两类状态码都有其他可能原因，需结合实际证据。接口的开关关闭或到期时，新请求返回 404；已进入应用的慢请求可能继续约 12 秒。日志可能包含敏感数据，分享前应限制范围并脱敏。

独立 timing 日志可以用响应 request ID 关联请求总耗时与上游耗时；access/error 日志若没有同一 ID，只能按实际时间窗口关联。`proxy_read_timeout` 限制的是相邻读取之间的等待，不是整个请求的绝对时长。

## 恢复与验证

以本轮回执中的 24 位运行 ID 替换 `RUN_ID`。root 控制的已安装控制器在自己的锁内验证本轮身份；502 只恢复核验过的订单服务，504 只关闭本轮开关。此直接 resolve 不写 CLI 事件；随后通过 CLI check 和 reset 记录检查及清理。

```bash
sudo /usr/bin/python3 -I -B /usr/local/libexec/opsdrill/n03/n03_502.py resolve RUN_ID
sudo bin/opsdrill check N03 --actor user --expect-run-id RUN_ID
curl -i --max-time 5 http://127.0.0.1:8080/health
curl -i --max-time 5 http://127.0.0.1:8080/ready
sudo bin/opsdrill reset N03 --actor user --expect-run-id RUN_ID
```

安全复位后可对同一 ID 重复 reset；若已有另一轮演练，期望 ID 不匹配时会拒绝。若控制器提示身份、配置或状态不一致，保留现场并检查，不要手动删除未知文件或停止未知定时器。

## 保护与限制

控制器为本轮注册 120 秒的 systemd 看门狗，504 开关另有最长 120 秒的单调时钟有效期。开关过期只表示应用不再接受它，不保证文件已经删除；看门狗和 reset 各自负责清理。运行中的请求不会因开关关闭而立即取消。虚拟机重启及暂停恢复行为需另行实测；Linux 单调时钟不计系统挂起时间，不应将该限制描述成墙上时钟保证。

## 自动验收

`sudo bash tests/contract/n03.sh` 自动测试两个变体，事件为 `actor=agent`。它验证实际故障、按 ID 恢复、检查、复位、重复复位和错误 ID 拒绝，可用于项目复盘和展示。

## 看门狗实机验证（2026-11-12）

在隔离恢复副本中，分别由 `actor=agent` 发起 502 和 504，先确认故障，再等待原有 120 秒定时器自行触发。502 的看门狗启动订单服务，504 的看门狗移除本轮慢接口开关；两次恢复检查和按运行 ID 复位均通过。证据分别保存在本机 `/var/backups/opsdrill/network-verification-fa3959f8c83831e5/N03-502.json` 和 `/var/backups/opsdrill/network-verification-fa3959f8c83831e5/N03-504.json`，并可通过其中记录的 systemd invocation ID 查本次日志。

此前一次 502 看门狗也启动了服务，但验证脚本因 systemd 回收瞬时单元后 `InvocationID` 为空而提前退出；该次的恢复检查未执行。随后改用服务自身 journal 中的 invocation ID 验证，并重新完成上述 502 测试。以上不代表已经验证虚拟机重启、挂起恢复或所有异常退出路径。
## 官方参考

[Nginx proxy 模块](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)、[Nginx 日志模块](https://nginx.org/en/docs/http/ngx_http_log_module.html)。

## 新机 502／504 及配置修复（2026-11-14）

新机首次 504 启动没有建立故障：其 systemd 服务缺少 `40-opsdrill-n03.conf`，受控慢接口即使门控文件存在也返回 404。该失败的 CLI 和控制器状态已归档在 `/var/backups/opsdrill/N03/failed-start-archive-f96990034f868371/`，失败事件保留；之后按同一控制器 run ID 安全复位，再在控制器确认干净后协调 CLI 状态。此轮不能记为成功演练。

补装固定的门控环境配置并重启实验 API 后，未开启门控时慢接口仍返回 404，业务 readiness 为 200。随后分别通过统一 CLI 验证实际 502 和 504、故障时 check、恢复后 check 及同轮复位；两次响应的请求 ID 分别与独立 timing 日志对应，错误日志在各自有限时间窗口内分别包含连接拒绝和上游超时的证据。错误日志没有与响应相同的请求 ID，因此只是按窗口关联。原始日志未加入安装包。

精简结果位于 `/var/backups/opsdrill/N03/gateway-evidence-018e9e687a49c41f/result.json`，SHA256 `884ba89f338fc635c522028126b71c338493d4eae3477386d17098b214f8e9e9`；事件和结果使用 `actor=agent`。该结果只覆盖本机两个有限请求，不代表所有 502／504 均由这两种原因造成，也不代表虚拟机挂起或重启后的行为已验收。

新版 bootstrap 在启动业务栈前准备此受保护 drop-in：已有相同文件时保留，冲突、不安全目录或符号链接时拒绝。目录创建、重复执行、冲突拒绝和模拟启动顺序已验证；新版安装包尚未在另一台空盘完成完整 bootstrap。
