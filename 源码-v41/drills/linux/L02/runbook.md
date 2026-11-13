# L02 排障与恢复

本变体使用独立 transient Nginx；默认在未授权的 19081 端口复现拒绝，再将专属配置切换到当时空闲且已允许的 8443。端口与策略会变化，每次启动前都重新检查。该做法不修改 SELinux 策略，也不代表完成 `semanage` 写入实操。

首次使用前审阅 `scripts/install_l02.py` 和本目录中的 Python 模块，将审阅后的安装器放到仅 root 可修改的位置，再以 root 执行该安装器并将本目录作为源目录参数。安装器核对固定摘要，拒绝覆盖不同版本或不安全路径。

1. 记录本轮 `run_id`，检查 `systemctl status opsdrill-l02-RUN_ID.service`、`journalctl -u opsdrill-l02-RUN_ID.service -b`、`getenforce` 和端口占用。
2. 检查审计事件与端口类型：`ausearch --input-logs -m AVC -ts recent`、`semanage port -l`。本机审计事件可能没有 SOCKADDR，判题会关联同一 boot、unit、invocation 和 PID 的 Nginx 端口日志与 AVC；这是一种相关性证据，不能排除极端 PID 复用或时钟漂移。
3. 使用 `tests/solutions/L02.sh RUN_ID user` 修复本轮专属配置，再执行 `sudo bin/opsdrill check L02 --expect-run-id RUN_ID`。
4. 使用 `sudo bin/opsdrill reset L02 --expect-run-id RUN_ID` 清理本轮。检查系统 Nginx、订单健康接口及 SELinux 状态。

专属服务运行上限为 120 秒；独立 watchdog 约 180 秒后尝试停止本轮服务并保留状态，随后仍需 reset。重启、锁长期争用或身份变化时不能保证自动恢复；状态不明时停止并检查，不要批量删除未知单元、配置或 SELinux 规则。

参考： [Red Hat Enterprise Linux 9：Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)；[systemd-run 官方手册](https://freedesktop.org/software/systemd/man/latest/systemd-run.html)。

## 恢复版本 v2 与中断边界（2026-11-13）

新轮次通过统一 CLI 使用 `/usr/local/libexec/opsdrill/l02-recovery-v2`；旧版仍保留，已有 CLI 状态按记录版本处理。新版启动前将随机启动标识写入受保护日志，看门狗可在 InvocationID 尚未写入时匹配同一标识和 unit 属性，再绑定身份；身份不明时拒绝并保留现场。`make contract-l02` 已在授权恢复副本通过正常故障、修复与复位。

代理 run `949c1b5837e9d7f934b51a26` 于隔离服务启动后、InvocationID 写入前注入受控异常；随后手动提前调用新版看门狗，确认它绑定本轮 InvocationID 并保留停止记录，再以该 ID 复位，清理检查通过。这不是定时器自然触发、SIGKILL 或断电测试，也不能保证跨重启恢复。`make contract-l02-prewrite` 会创建新一轮真实隔离服务，仅在确认空闲且获授权的实验机运行。

新版本源码位于本目录 `recovery-v2`，安装器为 `scripts/install_l02_v2.py`。以 root 执行前须将安装器和所需模块暂存至 root 控制目录、独立核对固定摘要；安装器接受模块目录参数，拒绝覆盖不同版本。不要从 devops 可写项目树直接以 root 执行安装器。旧评估目录及未知对象不应按名称删除。

代理 run `0ca533f01981bb1ec999bd7e` 在服务启动后、InvocationID 写入前注入受控异常，等待约 180 秒后由 systemd 定时器自然启动看门狗；看门狗匹配并绑定本轮身份，记录 STOPPED_OR_ABSENT，随后按相同 ID 复位且清理检查通过。该轮仍不是 SIGKILL、断电或跨重启测试。

标准入口 `inject.sh`、`check.sh`、`reset.sh` 均转发至统一 CLI，并接受相同的 `--actor`、`--expect-run-id` 等参数。`bridge.sh` 是保留的旧版直接入口，不生成统一 CLI 事件，也不跟随 v2 版本路由，仅用于经核验的旧状态；不要用它操作 v2 轮次。
