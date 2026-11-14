# 统一演练入口（候选版）

`bin/opsdrill list` 列出已注册的 L01–L04、N01–N04、M01、M02；`sudo bin/opsdrill status` 查看入口自身的受保护状态。L01、L02、L03、N02、M01，以及 N03 的 502/504 模式均支持通过统一入口 `start` 和 `reset`，运行身份由 receipt 与各自控制器共同验证。M02 的 start/reset 仍使用演练目录，直到它支持同样的运行身份校验。

```bash
sudo bin/opsdrill start L03
sudo bin/opsdrill check L03
sudo bin/opsdrill reset L03
sudo bin/opsdrill report
```

L01 默认使用 inode 变体，也可指定 `--variant deleted-open`；启动后先按演练提示修复，再执行 `check`：

```bash
sudo bin/opsdrill start L01 --variant inode
sudo bin/opsdrill check L01
sudo bin/opsdrill reset L01
```

deleted-open 的运行输出包含本轮服务名；确认其身份后可停止该服务释放句柄。完整范围和限制见 `drills/linux/L01/README.md`。

N03 默认使用 502 模式，会短暂停止实验订单服务；本轮恢复看门狗默认约 120 秒后执行：

```bash
sudo bin/opsdrill start N03 --variant 502
sudo bin/opsdrill check N03
sudo bin/opsdrill reset N03
```

看门狗仅在服务配置与本轮身份一致时恢复；遇到配置变更会拒绝操作，需人工检查。504 模式使用 `--variant 504`，运行输出给出本轮 `run_id`。按 N03 runbook 先用该 ID 执行 `resolve`，再用 `check` 验证恢复，最后 `reset`。开关最多有效 120 秒，到期不等于已清理演练状态。

M01 统一入口使用受保护的按运行 ID 控制器和独立 watchdog；先按 `drills/mysql/M01/README-owned.md` 安装和审阅，再启动、检查、修复及复位。旧的独立 M01 入口会拒绝接管统一入口的活动状态。

L02 使用专属 Nginx 单元和 SELinux 端口拒绝；先安装审阅后的 root 控制模块，再执行 `sudo bin/opsdrill start L02`。按 `drills/linux/L02/runbook.md` 用输出的 run ID 修复、检查并复位。服务的 120 秒运行上限和 180 秒 watchdog 不代替 reset。

N02 使用独立的网络命名空间。安装已审阅的控制器后，通过 `sudo bin/opsdrill start N02` 开始；输出的 `run_id` 用于按 `drills/network/N02/runbook.md` 定位和修复，再执行 `check` 与 `reset`。180 秒 watchdog 只尝试恢复故障规则，不代替复位；身份异常时会拒绝操作。

L04、N01、N04 的检查、修复和复位必须提供启动回执中的 `--expect-run-id`；N04 命令和已验证范围见 `drills/network/N04/README.md`。N01 独立异常回收尚未完成；N04 新版已验证一次启动中断后的同身份复位，其他异常时点仍需区分。

同一时刻仅允许一个入口操作；失败或中断后保留状态。所有权不明确时拒绝终止或清理，须先检查具体演练的状态。`reset` 在 L01、L02、L03、N02、N03 或 M01 已经独立检查为干净时可以重复执行。

`hint` 输出当前演练提示。`note L03 --kind diagnosis` 只记录诊断标记，不保存自由文本，避免将凭据或隐私写入事件日志。事件文件由 root 保护，默认不公开。汇总中的“非零检查”包含进行中的检查，不能直接解释为故障失败次数；早期 L03 和 N02 各有一次进行中检查被记录为 FAIL，原始记录保留；后续在确认仍处于演练故障时使用 PENDING 区分。

该入口尚未覆盖其余演练和完整提示级别、自由文本备注、自动化验收与 CI；不能仅凭目录或入口存在宣布 v1.0 完成。
