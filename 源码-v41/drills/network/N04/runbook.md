# N04 操作说明

只在已授权的隔离 VMware 实验机运行。先确认实验室标记、当前无冲突状态以及默认端口范围；使用 README 中统一 CLI 步骤，并保留 start 输出的 run_id。故障时 check 返回 1；resolve 后 check 返回 0；同轮 reset 成功后可再次 reset。任何身份不匹配、控制器失联、未返回 run_id 或没有完成凭证的旧轮，都应保留现场并核查，不能猜测删除 socket 或停止进程。

`make contract-n04` 是会实际注入故障的实验机契约；2026-11-13 在恢复副本通过一次，操作者标记为 agent。CLI 的连接复用是单连接 8 次请求的 TCP 实验；另外独立 Nginx upstream keepalive 对照和边界见 README。

参考：[Linux 内核 IP sysctl 文档](https://docs.kernel.org/networking/ip-sysctl.html)、[Nginx upstream 模块](https://nginx.org/en/docs/http/ngx_http_upstream_module.html)。

新版启动前已在受保护 CLI 状态中保存 run_id；异常中断时，以该状态中的 ID 调用 reset，必须经过同轮身份校验。新版状态清除后重复 reset 必须附加 `--n04-version recovery-v2`。无法证明身份时保留现场，具体实现及限制见 `recovery-v2/README.md`。
