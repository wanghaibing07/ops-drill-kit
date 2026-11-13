# L02：SELinux 端口拒绝

仅在有项目标记的 VMware 实验虚拟机运行。演练使用独立的 Nginx transient 单元和专属配置，不改系统 Nginx 或 SELinux 端口策略。故障端口和修复端口必须分别满足当前策略与空闲检查；冲突时拒绝启动。

2026-11-12 在 Rocky Linux 隔离恢复副本中，代理完成了真实 AVC 故障、配置修复、HTTP 验证及重复复位；另测 120 秒服务上限和 180 秒 watchdog 后的复位。恢复副本中的 SELinux 始终为 Enforcing。该记录可作为 AI 协作项目的真实实操经历，不代表项目全部验收完成。

调用前必须安装经审阅的 root 控制模块集，安装说明和诊断步骤见 `runbook.md`。watchdog 只停止本轮专属服务并保留状态，不代替 reset；异常或身份不明时保留资源供核查。
