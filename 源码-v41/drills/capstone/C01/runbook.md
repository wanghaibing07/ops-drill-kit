# C01 综合订单链路故障

本轮通过统一 CLI 注入 app-down，关联系统服务和网关状态。恢复时使用返回的 run ID，分别执行 `opsdrill check C01 --expect-run-id <ID>`、`opsdrill resolve C01 --expect-run-id <ID>` 和 `opsdrill reset C01 --expect-run-id <ID>`；异常或身份不明时保留现场，不猜测清理。

在授权恢复副本，run `ad64d4b1bad8954f34297fc9` 验证订单入口故障时 HTTP 502；恢复后订单查询、health 和 readiness 均为 200，错误 run ID 被拒绝，N03 清理状态为 CLEAN。受保护结果位于 `/var/backups/opsdrill/C01/contract-*/results.json`。此候选 check 对恢复返回 `RECOVERED_PARTIAL`，不代表跨层日志、用户通报、RCA 或完整验收均已完成。

`make contract-c01` 会在已确认空闲的授权实验机停止并恢复实验 API，运行新一轮验证。底层 N03 watchdog、owner 和 run ID 均需匹配；正常完成后保存清理记录，下次运行归档旧记录。源码在 `experimental/n03-c01`，root 运行前须将安装器和经审阅的文件暂存至受保护目录并校验摘要。

## 事件记录和新版控制器（2026-11-13）

新版 C01 控制器位于 root 控制的 `/usr/local/libexec/opsdrill/c01-v2/c01_control.py`，与旧版并存；统一 CLI 会先保存本轮 run ID，再调用新版。检查、修复、复位必须使用同一个 ID。若启动未确认或中断，先看 `opsdrill status` 里的 CLI 状态和控制器记录；身份不一致时保留现场，不从环境已恢复推断演练成功。旧的直接控制器入口不会自动补写事件。

CLI 记录注入、诊断标记、检查、缓解和清理事件，不存自由文本。`check` 的 `RECOVERED_PARTIAL` 在报告中显示 PARTIAL，不计算 MTTR。实测 run `290916121d117112af4c3fc3` 依次验证 502、错误 ID 拒绝、诊断标记、缓解和清理；报告按同一 ID 显示 PARTIAL，ready 为 200。

重新安装新版时，先将 `experimental/n03-c01/c01_control_v2.py` 与 `scripts/install_c01_v2.py` 复制到 root 控制、不可由其他用户修改的暂存目录，独立核验源码摘要 `29b84c493a889ff2ea6b624f23e3e98f6a15096eed5a648e676bed08d928b60a` 和安装器来源，再从暂存目录用 root 运行 `python3 -I -B <受保护目录>/install_c01_v2.py <受保护目录>/c01_control_v2.py`。安装器只创建独立目录或核验一致的既有安装；不能从 devops 可写的项目目录直接以 root 执行。安装器自身不能证明其执行前未被篡改。

已在同一轮 `290916121d117112af4c3fc3` 清理后重复执行 reset：返回非零及 `RUN_ALREADY_CLEANED`，状态未变且 readiness 为 200；这是安全拒绝，不是重复 reset 成功。`contract-c01-events` 现将此行为纳入检查。

## 官方参考

[Nginx 反向代理模块](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)、[systemd.exec 进程运行环境](https://www.freedesktop.org/software/systemd/man/250/systemd.exec.html)。

## 跨层小样本验证（2026-11-13）

run `5f290ba7199c8811bac94180` 在恢复副本中分别在注入前、故障时、恢复后各发起 3 个订单请求：状态依次为 200、502、200。对应阶段 Nginx 与 MySQL 服务保持 active，API 服务依次为 active、inactive、active；通过受保护的管理员配置执行固定只读查询，三个阶段均能查询旧库订单和数据库线程、锁等待计数。9 个请求的 ID 与独立 Nginx timing 日志中的状态逐项匹配。恢复后 readiness 为 200，按同一 run ID 复位；证据摘要为 `/var/backups/opsdrill/C01/cross-layer-851749c7f07ef22d/result.json`。

`make contract-c01-cross-layer` 可在确认空闲的授权实验机重复该真实故障采样，会短暂停止订单 API。它依赖已审阅并放在 root 控制目录 `/var/backups/opsdrill/Baseline/verify-candidate-20261113-v3` 的基线校验器及固定摘要；目标环境不具备该前提时拒绝。执行前必须信任并审阅项目树及命令，参见根 README 的特权信任边界。

每个阶段只有 3 个样本，不能证明全局 5xx 率回到基线，也不能证明时间窗口内不存在任何连接池错误；数据库计数是采样，并非完整根因排除。本轮没有代表用户填写 RCA 或实际发送用户通报。`check` 和自动报告继续为 PARTIAL，不计算完整 MTTR。

## 扩展跨层采样（2026-11-13）

受保护快照运行 `dc9942b87af69cd79a89b833`：故障前、故障中和恢复后各采样 25 次订单请求，状态分别全部为 200、502、200；每次请求 ID 均与 Nginx timing 日志状态匹配。对应阶段 Nginx 和 MySQL 均为 active，API 依次为 active、inactive、active；每阶段的数据库只读探测可用。复位后各服务 active、`/ready` 为 200。受保护采样结果在 `/var/backups/opsdrill/C01/cross-layer-d392e29518ba4e1d/result.json`；原始请求信息和日志不要公开。

这是三个有界窗口的请求样本，不代表全局 5xx 基线、完整连接池错误审计或人工排障。当前 `check C01` 按现有契约仍是 `RECOVERED_PARTIAL`；不能将采样通过写成完整自动验收通过。

## 有界网关窗口与连接池观测（2026-11-13）

应用的两个连接池现在分别提供单进程内、条件锁保护的错误计数和代次标识。观测接口只允许本机直连，拒绝带转发标头的请求；它不查询数据库、不输出凭据。计数按错误类别累计，多个底层错误可能属于同一次业务失败，不等于独立事故数。服务或池重建会改变进程或代次，不能跨代相减。

run `bc80cd9906e906bd4c389c8d` 在恢复副本中记录三个有限网关窗口，窗口内所有 timing 日志分别为 10 个 200、10 个 502、10 个 200；正常和恢复窗口的两个订单接口内容符合固定合成数据。恢复窗口的两次快照来自同一服务进程和各自同一池代次，七类错误计数均无新增；恢复窗口的应用 journal 留存 10 条记录且未匹配指定错误关键词。网关 5xx 在该有限窗口回到所采基线，复位后服务 active、readiness 为 200。原始窗口日志和结果仅存 root 保护目录 `/var/backups/opsdrill/C01/window-metrics-f84c5e33c068da77`，结果 SHA256 `736285e7e917d392a640454ee2ad528da6623a902032d78838bf72fcaaca1902`，不要公开原始日志。

这是针对本机目标网关和恢复窗口的自动观测，不代表其他时间或所有系统没有错误。基线阶段的旧进程没有连接池计数，故障期间 API 已停止；恢复窗口之外不能推断零增量。统一 `check C01` 仍返回 RECOVERED_PARTIAL，工单、复盘与讲解由人工完成。复现实验见 `tests/contract/C01-window-metrics.py`，执行前须把 CLI、测试脚本及其依赖放入 root 控制目录并核对摘要；实验会短暂停止并恢复 API，身份不匹配时保留现场。

## 离线复核有界证据

`scripts/audit_c01_window.py` 可在不输出原始日志的情况下复核 root 保护结果和日志摘要、三个窗口的状态与顺序、恢复窗口两个池的代次及错误计数、journal 身份和本轮 auto 事件。使用前将审阅过的脚本复制到 root 控制目录并核验其 SHA256 `78b47ef77f65089ef76bb6bbf28f42c850d25aa0c801f001c195f36df6f51e51`，再以 root 运行该副本，提供 `--run-id`、`--evidence-dir` 和 `--expected-sha256`。目录、身份、摘要或任一证据不符时拒绝。返回 `BOUNDED_OBSERVATION_PASS` 只表示有限窗口证据通过，统一 C01 检查和完整复盘仍为 PARTIAL；不要把它解释成全局无错误或人工演练。

审计还会验证三个观测窗口与注入、故障检查、缓解、恢复检查和清理事件的同轮时间顺序，缺失或错序时拒绝。

## 统一入口复核有限窗口

同一轮 `reset` 已成功后，使用 `opsdrill check C01 --expect-run-id <运行编号> --evidence-dir <受保护证据目录> --expected-sha256 <result.json摘要>`。统一入口核对当前清理回执、同轮事件顺序和受保护证据，成功返回 `BOUNDED_OBSERVATION_PASS`。普通 `check` 不带证据参数时仍保持原有 PARTIAL 契约。该结果只适用于有限技术窗口，不代替完整 RCA、人工复盘或全局零错误证明；重启后或新一轮覆盖回执时，统一入口拒绝，仍可依据独立审计入口复核历史证据。

更新后的 `tests/contract/C01-window-metrics.py` 会在根目录权限校验通过后补建缺失的受保护证据目录，并在同轮清理后自动调用统一有界判题。新机自动执行 `a9cb8428bd4c8551f074b984` 已验证整条契约通过；结论仍限定在该轮有限窗口。
