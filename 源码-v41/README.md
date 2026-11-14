# ops-drill-kit

Linux / 网络 / MySQL / Shell 故障诊断与自动化恢复套件。

## 项目目标

通过可复现的故障演练，练习 Linux 系统运维、
网络排障、MySQL 管理、Shell 自动化和故障恢复。

## 技术栈

- OS: Rocky Linux 9.8
- Database: MySQL 8.4 LTS
- Web: Nginx
- Language: Bash / Python
- Testing: ShellCheck / Bats
- Environment: VMware Workstation

## Project Structure

- lib/: 公共函数与安全护栏
- scripts/: 运维脚本
- tests/: 自动化测试
- docs/: 技术文档
- evidence/: 演练证据

## Current Progress

- [x] Rocky Linux 基础环境
- [x] MySQL 8.4 部署
- [x] 数据库账号权限隔离
- [x] Git 仓库初始化
- [x] Python 虚拟环境
- [x] 基础安全护栏
- [x] Nginx -> Python -> MySQL 最小业务链路（5 条合成订单）
- [x] 影子库 500,000 条合成订单及只读分页查询（旧接口仍使用原库）
- [x] M01 索引演练及慢日志采集
- [x] M02 行锁、死锁、1205 重试与同序加锁实验；统一 CLI 已完成真实 1213、恢复和重复复位验证（自动执行）
- [x] L02 SELinux 端口演练：真实 AVC、专属 Nginx 修复、CLI、复位与定时恢复已在恢复副本验证（自动执行）
- [x] N02 隔离 ACL 演练：控制器、CLI、复位及 180 秒 watchdog 已在恢复副本验证（自动执行）
- [x] L04 文件描述符上限：独立服务及统一 CLI 契约已在恢复副本验证（自动执行）
- [x] N01 DNS：统一 CLI 正常流程和一次 supervisor 异常退出后的定时回收已在恢复副本验证；其他中断场景仍需验证（自动执行）
- N03 网关：实测 502、504、恢复与复位；新机 504 配置缺失已修复，有限日志证据与失败记录见 Runbook。
- N04 临时端口：统一 CLI 正常流程及独立连接复用已在恢复副本验证；启动中断后按预写身份恢复已做单次实机验证，其他异常时点仍待覆盖；Nginx upstream keepalive 已另做隔离对照，尚未接入 CLI（自动执行）
- [x] M03 连接耗尽：隔离 MySQL 的统一 CLI 故障、恢复与重复复位已在恢复副本验证；未证明业务 API 联合端到端（自动执行）
- M04 PITR：隔离双实例完成合成数据恢复；v4 已在新机验证停止命令返回后、完成状态写入前的受控中断及复位。磁盘总配额和完整应用、数据库一致性恢复仍未证明（自动执行）。
- C01 综合故障：在新机的三个有限请求窗口完成故障、恢复和清理，统一 CLI 的有界证据检查通过；普通恢复检查仍为 PARTIAL，有限窗口不代表全局零错误或完整 RCA。
- 13 类演练均有实机事件；各演练的范围、异常边界及剩余限制以对应 Runbook 为准，不能据此声称全部完整验收。

## 基线与重建状态

现有实验副本的只读基线检查见 `baseline/README.md`；`baseline/verify` 检查服务、接口、MySQL 回环监听和固定合成数据。独立空盘 VM 使用 v27 安装包完成一次完整 bootstrap，基线 19 项和首轮 L03 受控模拟通过；后续 M02、C01 的修复和验证通过受控续接完成。此版 bootstrap 新增 M02 目录准备步骤，已单独测试，但此版整包尚未再次在空盘执行完整 bootstrap。安装包外层的 `FRESH-VM-INSTALL.md` 描述目标身份核验、传输、暂存和 bootstrap 顺序。root 运行前须依说明把工具暂存至受保护目录并独立核对来源。

## Diagnostics

- `scripts/triage60.sh [--json]`: bounded read-only system checks; command failures are recorded individually.
- `scripts/log_radar.sh /path/to/access.log`: aggregate combined or JSON access logs; source addresses are grouped by network, query strings are omitted, and unknown paths are represented by hashes. Timing statistics are unavailable when the log has no timing fields; P95 requires at least 20 samples.
- `scripts/netcheck.sh`: local health endpoints and known lab namespace checks; missing namespaces are reported as unknown.
- `scripts/backup_verify.sh /path/to/backup`: validate the listed SHA256 hashes and gzip streams. Integrity checks do not replace an isolated restore.
- `sql/mysql_diag.sql`: read-only MySQL status and lock-wait counts; use an existing protected option file for authentication.
- `scripts/verify_m04_evidence.py`: check the hashes and consistency of a specific existing M04 evidence bundle; see `docs/runbooks/M04-evidence.md`.

These commands print potentially sensitive operational information locally. Review and redact output before sharing or committing it. Current VM wall-clock synchronization must be checked separately.

## L03 status

The controlled I/O simulation, health checks and identity-bound cleanup have passed on the lab VM. One separately measured throttled run observed elevated system iowait; this is not evidence of a hardware fault or proof that the workload was its sole cause. See `drills/linux/L03/runbook.md`.

## Safety

各演练必须通过其自身的实验机、资源身份和权限护栏；不同控制器使用的护栏并不完全相同。

当前 `bin/opsdrill` 会以调用者权限执行项目树中的 CLI，而项目目录由普通用户控制；文件单独为 root 所有也不能抵消可写祖先目录的影响。因此执行 `sudo` 前必须信任并审阅项目树；root 控制的独立演练控制器并不使整个 CLI 自动成为抗普通用户篡改的特权边界。安装器及基线工具应按各自说明先安全暂存并核验，不能把脚本运行后的自检当成对其运行前完整性的证明。

禁止操作宿主机全局网络、防火墙及非实验资源。

## Status

Development in progress.

M02 操作说明见 `docs/runbooks/M02-row-lock-deadlock.md`；部分本轮实验的外部受保护证据索引见 `evidence/lab-results-index.json`；历史副本的原有索引独立保留，不随干净安装包复制原始记录。

## 自动结果

在授权实验机运行 `sudo make generate-results`，从受保护事件文件生成 `docs/results.md`；相同事件重复生成结果一致。早期文字记录保留在 `docs/results-m02-history.md`。报告区分 `auto` 与 `user`，只在同一执行者和同一启动周期内计算可用时间；L03 证据齐全且完成清理时显示受控模拟 PASS，C01 普通报告仍为 PARTIAL，两者均不计算完整 MTTR。C01 有界证据应另用统一有界检查复核。分享前应检查报告及证据是否适合公开。

## Testing

在项目目录安装 `requirements.txt` 并准备 ShellCheck、Bats 后：

- `make lint` 执行 CI 使用的 ShellCheck 检查。
- `sudo make test` 使用项目 `.venv` 运行离线单元测试、需要 root 的离线所有权测试和 Bats。可用 `PYTHON=/path/to/python` 指定已安装依赖的解释器；真实服务测试默认跳过。
- 如需只读检查运行中的业务服务，可在授权实验机设置 `ORDERGUARD_INTEGRATION_URL=http://127.0.0.1:8080` 后运行 `.venv/bin/python -m unittest discover -s tests -p test_stage3_api.py -v`。
- `sudo make contract-l01`、`contract-l02`、`contract-l04`、`contract-m01`、`contract-m02`、`contract-m03`、`contract-m04`、`contract-n01`、`contract-n02`、`contract-n03`、`contract-n04`、`contract-c01` 分别运行现有真实注入契约；它们会改变实验资源，只能在已确认空闲的授权 VMware 实验机执行。运行前核对对应演练的 Runbook，失败时检查保留的状态后再处理。
- 固定种子新机的 M02 使用 `sudo make contract-m02 M02_VERSION=baseline-v2`；旧基线使用默认的 `legacy`。`sudo make contract-c01-window` 在有限窗口采样并于清理后调用统一有界判题；该结果不等同完整 RCA。

这些入口不代表 13 个演练的完整契约已完成；GitHub Actions 只执行离线检查，不模拟 Rocky Linux 的 systemd、SELinux 或故障注入。

## 关于本目录与归档清单

目录内 `BUNDLE-MANIFEST.archive.json` 记录的是归档时候选包的文件摘要，共 543 个条目。

为对外发布，源码做过一次整理：事件记录中的执行者标注字段已整体移除，相关参数、校验与报告分组同步调整。因此当前文件与清单摘要不再逐一对应，清单只用于说明归档时的包结构，不能作为当前文件的完整性校验依据。

整理后已逐个文件通过语法检查（Python、Shell、JSON），但未在实验机上重新执行演练。
