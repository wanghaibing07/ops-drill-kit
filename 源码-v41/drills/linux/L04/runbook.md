# L04 文件描述符上限

本演练只启动有时限的独立临时服务，不改变系统默认限制或现有业务服务。低上限下实际出现 EMFILE；修复时通过本轮 run ID 创建较高上限的临时服务。

使用 `opsdrill start L04 --actor agent` 取得 run_id；`check`、`resolve`、`reset` 都需要 `--expect-run-id`。检查返回 1 表示确认故障，修复后返回 0。`sudo make contract-l04` 执行真实注入，仅限授权实验 VM。

服务超时或启动时身份未能落盘可能需要人工核查，不能按名字批量停止未知单元。代理运行不是用户本人练习。

隔离恢复副本实测：代理以统一 CLI 完成故障检查、修复、恢复检查、复位和重复复位，run ID `d3fbc76eac0972505e8378bd`；错误 run ID 被拒绝。该结果不代表用户本人练习，也不证明异常中断或重启后的完整恢复。

## 官方参考

[systemd.exec：进程资源限制](https://www.freedesktop.org/software/systemd/man/250/systemd.exec.html)。
