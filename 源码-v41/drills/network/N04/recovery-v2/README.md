# N04 recovery-v2 候选交接

CLI 基线：上级目录 `opsdrill_cli.n04.candidate.py`，原始字节 SHA-256 为 `6212345ed4443fe603d90aadb63482667530829e46ac8d24dfb15946d61489de`。`cli-recovery-v2.patch` 是相对于这一基线的差异；`opsdrill_cli.recovery-v2.candidate.py` 是完整候选。真实目标若摘要不同，必须重新审核合并。这里没有安装、连接或操作 VM。

## 协议与可证明范围

- CLI 在调用控制器前随机生成 96 位 run ID，并将 ID、`n04_version=recovery-v2` 和 STARTING 同步写入受保护状态文件。写入失败不会调用控制器。控制器使用该 ID 先独占创建目录并同步父目录，再独占持久化包含另外 256 位随机 token、boot ID 和安装摘要的 intent；只有随后才尝试启动 transient unit。已有目录绝不再次启动，随机碰撞或启动中断均保留现场。
- `reconcile RUN_ID` 从 intent 获取 token，核对当前 boot、已安装文件摘要、专属 transient unit 的预期启动参数（含 token）、InvocationID、PID、启动 ticks 和 root socket 的对端 PID；通过同一受认证 socket 的 status 后才持久化 identity。已有 identity 必须完全一致。它不重新启动服务、不依据 ID 或 unit 名猜测归属。token 出现在 unit 参数中，并非可对抗 root 的秘密；这些检查依赖受保护目录、可信 root 和已审阅的二进制来源，存在系统调用间竞态。
- CLI 对新状态的 STARTING/NEEDS_RESET 可按同一 ID 发起 reset；缺少 identity 时控制器只尝试上述活体 reconcile，成功后才执行既有受认证 reset。不能证明时拒绝，不删除 socket、目录或 unit。intent 写入不完整、CLI 在启动前中断、unit 尚未就绪或已退出、身份变化、重启、记录损坏、应答丢失等均可能需要人工核查；重试不是重新 launch。
- 原版路径 `/usr/local/libexec/opsdrill/n04`、原 `/run/opsdrill-n04` 和原 unit 名保持不变；新版使用兄弟安装目录 `/usr/local/libexec/opsdrill/n04-recovery-v2`、运行目录 `/run/opsdrill-n04-recovery-v2`、unit 前缀 `opsdrill-n04-v2-`。安装器采用固定字节摘要和不覆盖既有不同文件的规则；部分失败可留下文件。安装器自身仍须从独立可信渠道验证。新旧凭证不会互相迁移或重写。
- 已有 CLI 状态没有版本字段时按 legacy 路由；带新版字段时严格按新版路由，未知版本拒绝。同一状态下显式指定不同版本拒绝。无 CLI 状态时 reset 默认按 legacy 路由以保留旧版完成凭证重试；新版完成后若需重试，显式指定 `--n04-version recovery-v2` 和原 `--expect-run-id`。两者都仍要求对应生命周期的受保护完成凭证，未知 ID 不成功。
- 成功的主动 reset 只能说明收到了经过同轮身份认证的 worker 恢复响应，并按既有规则确认 service 已停止、写入完成凭证；不能据此证明匿名 network namespace 没有任何其他引用。服务超时、消失或退出不构成上述 reset 证据，也不产生完成凭证。这里不承诺异常自动清理全覆盖，不删除未知旧 socket。

## 将来交接使用提示

在未来经授权的隔离 VM 中，独立审阅和验证安装器及源目录后，安装器接口为 `/usr/bin/python3 -I -B install_n04_v2.py REVIEWED_SOURCE_DIR`；它只安装新版控制器和 worker，不替换 CLI。CLI 替换/合并和部署应另行审核实施。原始字节必须不变，换行转换会导致摘要验证失败。需要恢复启动中断时，先从 root 控制的 CLI N04 状态获取预写的 ID；以新版 CLI 的 `reset N04 --expect-run-id ID` 走同身份接续。也可由审核者使用新版控制器 `reconcile ID` 诊断，但成功仅证明当时的活体归属，之后仍须同 ID reset。若状态已删除而需重试新版已完成的 reset，附加 `--n04-version recovery-v2`。不得对未知版本盲目尝试清理。

受限本地测试：在本目录运行 `python -X utf8 -B -m unittest -v test_recovery_v2`。这些是 mock/临时目录测试，没有运行 Linux/systemd、socket 对端、namespace 或真实安装；旧基线测试通过也不代表新版 VM 集成已通过。需要未来由唯一 VM 执行者按实际系统验证 systemd 属性格式、身份握手、断点与拒绝路径、历史凭证兼容性以及 namespace 引用边界。

## 契约同步候选

`N04-cli.recovery-v2.patch` 相对于 `project/tests/contract/N04-cli.sh` 的 SHA-256 `1cb97289ca50debac15d665276f404c20265a19c70ab5af30772e5ae192e3a73`；`N04-cli.recovery-v2.candidate.sh` 是完整候选。补丁在目标 project 根目录检查并应用，目标有其他修改须重新合并。它根据回执严格区分 V1/V2，在 state 与回执一致后才继续；新版完成后的重复 reset 显式选 `recovery-v2`，原版默认路由保留。未知 ID 分别检查适用版本；可通过 `N04_LEGACY_COMPLETED_ID` 提供真实旧凭证做额外检查，没有则显示 SKIPPED。契约依赖真实目标的 report.py，未在 VM 上执行。

`test_contract_recovery_v2.py` 用 Git Bash 和假 CLI 本地验证两版的选择、旧凭证可选分支、无回执和状态不一致时拒绝 reset；假 CLI 不证明 VM 成功。真实中断的可控断点、身份核对、判定和局限见 `interruption-verification.md`，特别是 identity 落盘前窗口需要独立隔离的插桩测试构建，不应声称其测试了完全相同的发布字节。
