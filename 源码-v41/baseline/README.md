# ops-drill-kit 基线候选

## 2026-11-13 新机实测与当前边界

在独立空磁盘安装的 Rocky Linux 9.8 虚拟机上，通过几段受控续接完成了 MySQL 8.4.13 初始化、业务栈部署和 500000 条订单导入。独立检查确认 500 个商户、500000 条订单、商户 88 的 25000 条订单，重复订单号和孤儿订单均为 0，11 个导入批次记为 DONE；基线检查通过。L01 的 inode 耗尽与 deleted-open 两种变体完成注入、修复、检查及清理，演练操作者为 agent。

这次新机安装中，原候选先后遇到 MySQL 仓库默认版本、空日志文件、Python 导入作用域和演练状态目录缺失问题；旧失败记录保留，通过核实现场和单独账本续接。现在新增的 `bootstrap.py`、`orchestrate.py` 和管理员初始化修复已做针对性测试，但**修复后的完整一键从零部署尚未在另一台干净系统实测**，不能将本次多段续接说成一键部署成功。以下历史记录保留当时的证据范围，若进度描述与本节不同，以本节为准。

新 bootstrap 仍要求预先安全准备普通用户项目与 root 控制、独立核验摘要的工具暂存；绝不能将 `devops` 可写项目树当作 root 执行入口。失败或中断会保留状态并拒绝自动重试，尤其不能盲目重复 MySQL 初始化或导入。L03、C01、M04 和完整契约仍须按实际证据继续验收。


这里提供 `baseline/verify` 只读验收入口和 `baseline/deploy` 部署骨架。它们检查或使用实验机上已有的 `/opt/ops-drill-kit` 项目，不复制旧源码或 README。当前部署骨架只准备服务凭据 drop-in，**不是完整安装器**。

## 在授权实验机上使用

2026-11-13 在授权恢复副本上，从 root 控制的暂存目录运行 `verify`，环境、服务、HTTP 和固定数据库数据检查通过；早期 `deploy` dry-run 因现有其他 drop-in 包含相关凭据配置而保守拒绝；后续加入匹配配置识别后再次 dry-run，确认现有配置且未写入。完整重建仍未验证。将 `baseline` 目录安全地放到 root 信任的目录下；文件及祖先目录应为 root 所有、不可被组或其他用户写入。以下假设当前目录是放置候选的目录，通过 Python 运行，不依赖 Windows 传输时保留的可执行位：

```bash
sudo python3 baseline/verify          # 只读检查
sudo python3 baseline/deploy          # 默认 dry-run，显示将创建或跳过的配置
sudo python3 baseline/deploy --apply  # 仅创建缺失的两个凭据 drop-in
```

两个入口都要求 root、VMware 和 `/etc/opsdrill-lab` 的固定标记；失败时不会访问服务、HTTP 或数据库。部署还要求 `/opt/ops-drill-kit` 和其 `baseline` 目录已存在且路径中无符号链接，但允许它们归 `devops` 等普通用户所有。项目树只是检查对象，不是 root 写入的可信输入；不会以 root 执行其中的代码。当前只支持已加载的单元文件位于 `/etc/systemd/system/orderguard-api.service` 或 `/usr/lib/systemd/system/orderguard-api.service` 的情况。

**在用 root 执行这两个候选工具之前**，管理员必须确认 `baseline/verify`、`baseline/deploy`、`baseline/common.py` 和它们的所有父目录都由 root 安全控制，不能从 `devops` 可写的项目目录直接用 root 运行。`deploy` 还会检查自身和 `common.py` 为 root 所有、非组/其他用户可写的普通单链接文件及其父目录；但任何脚本的运行时自检都不能使执行前已被篡改的脚本变得安全。服务单元、目标 drop-in 及其父目录、凭据文件等 root 写入所依赖的输入仍要求 root 安全控制。

`deploy` 检查已存在的 root:root 0600 凭据文件 `/etc/opsdrill/orderguard-app.password` 和 `/etc/opsdrill/orderguard-stage3-reader.password`，不读取或创建密码。它使用候选工具内与已审阅源码快照一致的固定 Stage 3 配置模板，并为旧库准备 `mysql-password` drop-in；不读取普通用户可写项目文件作为 root 写入内容。现有内容一致或已加载相同凭据时跳过；同名凭据指向其他位置、存在其他相关 drop-in 或重置时停止。目标文件内容冲突时，dry-run 不写入；`--apply` 先把冲突文件内容备份到 `/var/lib/opsdrill-baseline/backups/<随机标识>/` 后停止，绝不覆盖，也不创建其他待安装文件。锁与备份都位于 root 控制的 `/var/lib/opsdrill-baseline`（0700），不会写入 `devops` 可写的 baseline 目录。备份文件权限不宽于 0600，不保留原文件 ACL、标签等元数据。重复冲突执行会产生新备份。

`--apply` 使用锁和排他创建，可能在异常中途留下部分新文件、锁或备份；保留现场核对后重跑。它**不会**创建账号、导入数据、安装包、设置密码、修改 Nginx、执行 `daemon-reload` 或启动/重启服务。新配置可能在后续 systemd 重载或服务操作时生效；这些操作要在检查完整部署、变更影响和恢复方式后另行执行。退出码：0 为检查或操作成功；1 为部署护栏或 I/O 失败；2 为冲突或验收未全部通过。

## 验收范围

`verify` 输出 PASS、FAIL、UNKNOWN、WARN 或 INFO；FAIL、UNKNOWN 或 WARN 都会使退出码非零，INFO 仅提供背景。它只读取项目文件元数据，不执行项目代码或虚拟环境解释器，并对所检查对象分别输出实际 UID、GID、权限和风险：非 root 属主是信息提示，不单独判失败；组或其他用户可写会告警。即使文件本身由 root 所有，只要其父目录可由普通用户修改，也不能作为 root 可信输入。它检查：

- Rocky Linux 9.8、VMware、标记和 SELinux Enforcing；项目源码、配置、SQL、生成器及虚拟环境解释器是否存在，以及它们的所有权和权限。
- 管理员配置及两个凭据文件的元数据；systemd 已加载的单元文件、用户、工作目录、启动命令关键项、两项凭据和 Stage 3 socket；MySQL、API、Nginx 服务活动状态。若 systemd 将 `LoadCredential` 显示为 `[unprintable]`，仅在 `NeedDaemonReload=no` 且加载的 drop-in 路径清楚时，按 systemd 返回的顺序只读检查 root 保护的 unit 和 drop-in 中的凭据映射；文件无法安全读取、语法超出支持范围或状态不明时为 UNKNOWN。不会打开映射指向的密码文件。
- 本机 `127.0.0.1:8080` 的 `/health`、`/ready`、`/orders/1001` 和 merchant 88 分页接口的固定响应。请求可能产生正常访问日志，数据库 SELECT 也可能被服务器记录。
- MySQL 8.4，以及原 seed 的五笔订单、影子库 500 个商户、500000 条订单、merchant 88 的 25000 条订单和两个边界订单号。数据库只通过固定本地 socket 和 `/etc/opsdrill/mysql-admin.cnf` 执行固定 SELECT；不打印配置、密码、客户端错误、查询输出或 HTTP 响应正文。查询可能耗时，超时或权限不足为 UNKNOWN。

管理员配置必须是 root:root 0600 普通文件。`verify` 在进程内短暂解析该文件，只接受一个 `[client]` 节及 `host`、`user`、`password`、`socket`、`protocol` 选项；要求 `user` 存在。`host` 可以省略，存在时只能为 `localhost` 或 `127.0.0.1`；如设置 socket/protocol，必须对应固定本地 socket 和 SOCKET 协议。include、续行、重复字段、其他节或选项均被拒绝并报告 UNKNOWN。不会记录、输出或持久保存配置值；解析异常也只报告通用状态。

MySQL 客户端使用 `--defaults-file`，并在命令行强制 `localhost`、SOCKET 协议及 `/var/lib/mysql/mysql.sock`，命令参数不含密码。客户端自身需要读取选项文件进行认证；检查与执行期间配置必须保持不变。

这些是最低验收条件，不证明全部 500000 条记录的内容、账号最小权限、备份恢复、依赖包完整性、Nginx 配置正确性或演练端到端行为。快照中 `app/main.py` 引用的 `app/n03_slow.py` 未提供；Nginx 配置引用的 `orderguard_timing` 定义也未提供。须以实验机上的实际文件为准，缺失时补齐并单独验证。

目前没有实现操作系统软件安装、Python 依赖安装、数据库及账号初始化、50 万条数据装载、Nginx 安装配置或服务启停。快照中的 `sql/003_stage3_schema.sql` 不是幂等脚本；`scripts/provision_stage3_reader.py` 有既有环境和数据前置条件，失败也可能留下部分状态。本骨架不会调用它们，不能声称完成可复现业务部署。

## 回退与本地测试

本骨架只可能创建上述两个 drop-in、锁和冲突备份。回退前核对哪些文件由本次创建，保留已有配置；如需移除新增文件或恢复备份，应检查当前文件、原属主、权限、ACL、SELinux 标签及 systemd 生效状态，再单独处理并按需重载。不要直接删除整个 baseline 目录。

在 Windows 本地运行 `python -X utf8 -m unittest discover -s tests -v`。测试使用模拟服务和文件权限，不连接 VM，也不替代 Rocky Linux 上的 systemd、SELinux、MySQL 或真实权限测试。

## 已加载凭据配置的识别

当 systemd 确认不需要重载，且同目录经固定摘要校验的 `verify` 证明已加载服务和两项凭据与预期一致时，`deploy` 会将缺失的目标 drop-in 标记为 configured，不重复创建。如果目标文件已经存在但内容不同，仍报告冲突并拒绝覆盖。任何无法确认的情况均回到原有保守检查。此识别不代表全新安装已完成。

## 合成订单文件准备

以 `devops` 用户在 VMware 实验机上运行 `python3 baseline/seed_orders.py` 查看缺失文件，追加 `--apply` 才生成。工具复用固定版本的造数逻辑和种子，准备完整 50 万条参考文件、前 1000 / 1001–50000 文件以及后续九个 5 万条批次；每个文件必须匹配固定 SHA256。已有文件摘要或权限不符时拒绝覆盖；中断留下 `.seed-stage-*` 时保留并要求检查。

2026-11-13 已以 `devops` 用户在独立临时目录生成并验证全部 13 个文件，第二次执行没有替换文件；现有实验数据目录上的 dry-run 和重复 apply 均未创建文件。该步骤只准备 TSV，不安装 MySQL、不创建数据库或账号、不导入数据；完整重建仍未完成。

## 隔离 MySQL 数据导入试验

`baseline/isolated_mysql_probe.py` 是独立试验入口，**不是 deploy，也不能用于现有业务 MySQL**。它复用已安装的 root 控制 M04 v2 隔离实例控制器，创建本轮两个 socket-only MySQL 实例，只向本轮 target 写入；不使用业务 socket、账号或库。它使用固定摘要验证原有 SQL 和 11 个不重叠数据段，以严格检查的有界 INSERT 批次导入，不启用 `local_infile`。参考用的 50 万条和 5 万条文件与分段重叠，不作为额外批次导入。目标是原 SQL 固定的 `orderguard` 和 `orderguard_stage3` 名称，但只存在于本轮隔离实例。

2026-11-13 run `fbbe186e7cd0bc17` 在恢复副本上运行：原始三个 SQL 初始化完成，11 段共导入 500000 行，订单数和唯一数均为 500000，商户 88 为 25000；按自增 ID 顺序从数据库导出 TSV 的 8 个数据字段（不含自增 ID）的 SHA256 与固定 50 万参考摘要一致。隔离实例在导入前后 `local_infile=OFF`；本轮实例按绑定身份停止，数据目录和受保护状态保留于 `/var/tmp/opsdrill-m04-run-fbbe186e7cd0bc17` 和 `/var/tmp/opsdrill-m04-controller/fbbe186e7cd0bc17`。试验后现有业务库 `local_infile=OFF`，MySQL、Nginx、API 活动，`ready=200`，SELinux Enforcing。

试验脚本的 SHA256 为 `eb204479ec2916101fe4b959f3f05d37f50dd7180e4a777ea1c8077b8fec786c`。在作为 root 运行前，必须先将它复制到 root 控制、不可由普通用户修改的暂存路径，独立核对脚本摘要及所有祖先目录，再以 `python3 -I -B <受保护目录>/isolated_mysql_probe.py` 运行；**不能直接以 root 执行 devops 可写的项目文件**。脚本只使用绑定到本轮身份的隔离实例；会创建保留的 MySQL 数据目录并要求 `/var/tmp` 至少 4 GiB 可用空间。

`baseline/db_batch.py` 是试验脚本内嵌的字段转换源码，测试会核对其与内嵌副本完全一致。试验在每段提交前写入状态；异常、中断或身份不明时标记或保留现场，不自动推测重试、删除或清理。MySQL DDL 隐式提交，因此建库或导入中断不能视为自动回滚；提交与状态落盘之间的中断也未经过实机测试。每段导入独立提交，并非全部数据的一次原子提交。`local_infile` 是检查导入前后状态，并非连续采样。

此证据仅覆盖当前机器的独立实例和合成数据，不覆盖操作系统安装、数据库账号和权限、迁移修复、业务服务接管、部署至干净虚拟机或从零执行 `deploy → verify`。

### 隔离实例事务失败验证

run `69a59012a3329201` 在另一套独立 MySQL 实例中，先确认目标表为 InnoDB，再于事务内写入前 1000 条并故意执行不存在的表查询；MySQL 客户端返回失败并断开后，另建连接确认订单表为 0。随后仅在确认回滚后重新导入这 1000 条，确认数量为 1000、隔离实例 `local_infile=OFF`，并按本轮身份停止两个实例，保留数据及状态。业务服务检查仍为活动且 `ready=200`。

重现入口 `baseline/isolated_mysql_rollback_probe.py` 的 SHA256 为 `d3b06b8e9d7a6f64988ee37a42662712c00efd00fd0b0c8c5c3d27b2873a9676`，须按上节相同的 root 受保护暂存及摘要核验方式运行。此测试是 SQL 语句错误后连接关闭导致的事务回滚；不是 SIGKILL、断电、DDL 中断或提交成功后状态未落盘测试。InnoDB 回滚后自增序列可能出现空缺，不能由此假设重试后的 ID 与首次完全一致。

### 提交后账本未更新的受控实验

run `9544b929c2f2a7d9` 在独立实例中持久化首批“进行中”记录，启动子进程将 1000 条写入并提交；子进程随后直接退出，没有修改该记录。仍在运行的父进程读取保护状态、核对本轮实例身份，然后检查表内行数和按 ID 顺序导出的 8 个数据字段摘要，识别出数据库匹配“本批已提交”的内容，未重新导入。本轮实例按身份停止并保留资源，现有服务保持活动且 `ready=200`。

`baseline/db_journal.py` 只做保守分类：要求调用方独立核对实例身份，并提供可信来源数据算出的批次前后摘要；只有行数与对应摘要同时匹配才分别报告匹配批次前或批次后，否则要求检查。它不会读数据库、持久化状态或自动重试。重现入口 `baseline/isolated_mysql_commit_gap_probe.py` 的 SHA256 为 `7744967bbc82feb111b82b4d5c70bd6ca2ae9c7957db5987dd0f67490cf0ccd1`；必须按上节受保护暂存要求执行。

这是一个子进程在提交后主动退出、父进程仍存活的受控实验；没有测试整个控制器进程被杀、断电、跨重启或自动断点续传。分类器尚未接入 `baseline/deploy`，本实验不代表部署已具备自动恢复。

### 持久化批次记录候选

`baseline/isolated_mysql_probe_v2.py` 在原试验上增加批次记录：提交前持久化本段边界、输入 SHA 和此前/此后连续数据前缀 SHA；提交、无警告且行数检查后，写入已确认批次并清除进行中记录。写入仍通过受保护控制器状态文件的原子替换和目录 fsync 完成。若提交完成但记录尚未更新，进行中记录保留，不能据此盲目重跑；需先确认实例身份并核对实际数据。计数与无警告本身不等于全量内容核验，完整流程末尾仍要求八字段全量摘要匹配。

run `e5656e27910dbc2a` 使用仅运行首批的测试变体，真实导入 1000 条并检查受保护状态中已记录一个完整批次、无进行中批次，随后按身份停止实例并保留现场。业务服务活动、`ready=200`。这是新版**单批**实测；新版的完整 11 批流程及中断自动恢复尚未实测，`baseline/deploy` 也尚未接入它。此前 50 万行完整结果来自原版。

新版完整入口 SHA256：`25d578ff3b9d729680775acb749964d99fa3be3b25a5f7fd8d52d0ac72a32715`；单批试验入口 `baseline/isolated_mysql_ledger_test.py` SHA256：`9eb9df6b5af9d62e718f325f359ca5c537c70c172b6e79bc5690b5ea201a1d9a`。均需按前述要求放入 root 控制目录、独立核对摘要后运行。

### 独立只读判别入口

`baseline/reconcile_mysql_import.py <run_id>` 读取 v2 的受保护记录，不修改账本、不续传、不停止实例。它要求 VMware 实验标记、同一启动周期、正在运行且身份可验证的本轮 socket-only MySQL、排他锁、完整且与固定输入摘要一致的批次账本；再以一致性快照读取行数及 8 个数据字段的有序摘要。只有与当前批次前或批次后的数量和摘要均一致时，分别输出 `MATCHES_BEFORE_BATCH` 或 `MATCHES_AFTER_BATCH`；其他情况返回 `NEEDS_INSPECTION`。结果只是该一致性快照的观察，不授权直接重试：`MATCHES_BEFORE_BATCH` 不能排除另一个尚未提交的事务或孤儿导入进程稍后提交，`MATCHES_AFTER_BATCH` 也不单独证明写入者身份。继续之前还需证明旧工作进程及其子进程均已退出并持有排他控制；当前工具尚未提供这一证明。读取 SQL 和打开锁文件仍可能产生正常数据库或系统审计记录。

run `8064c776dddb149d` 实测：首批提交前得到 `MATCHES_BEFORE_BATCH`；子进程提交后退出而账本仍为进行中时得到 `MATCHES_AFTER_BATCH`；两次判别前后账本文件 SHA 不变，随后身份绑定停止两个实例、保留资源。对已停止的实验和不存在的 run ID，工具返回非零并拒绝判断，既有状态摘要不变；业务服务活动且 `ready=200`。该测试的父进程保持运行，不是控制器 SIGKILL、跨重启或断电测试。

入口 SHA256 为 `22eafb2575f62eee99dd0d1381143b5b39c32fda0a4b7873cfa00de6b53112e8`；测试变体 `baseline/isolated_mysql_reconcile_test.py` SHA256 为 `e4ed192d40b9b196de2025b720e6adbceb87a08652896fed8d8c121a69cfaf9c`。两者均须先按前文暂存至 root 控制目录并独立核对摘要；运行判别工具时传入明确的 16 位 run ID。当前不支持已停止或跨启动周期的实例，不会清理、重启或接管服务，也未接入 `baseline/deploy`。

### 专属工作进程的受控强杀实验

run `575514bf1153243d` 在授权恢复副本启动独立 transient systemd 测试单元，显式设置 `KillMode=control-group` 和 60 秒运行上限。记录 unit、InvocationID、进程身份及控制组后，只向本轮单元的主进程发送 SIGKILL；确认主进程和事先核验的子进程退出，控制组为空或已消失。受保护证据位于 `/var/backups/opsdrill/Baseline/supervisor-575514bf1153243d`，业务服务保持活动且 `ready=200`。这是独立的模拟工作进程实验，没有连接数据库，不能推断数据库导入或自动续传已具备相同保证；若 unit 被回收、身份或子进程状态不明，仍须保守拒绝。

重现入口 `baseline/systemd_worker_supervision_test.py` 的 SHA256 为 `a450ae04dc37304e63b94692f69a4521ff0d6782f39270e9cfc8ba27fa21be82`。该脚本会启动一个最多 60 秒的 root 测试单元并对其主进程发送 SIGKILL，须在授权空闲 VM 中，按前述 root 受保护暂存与摘要核验方式执行；它不会重置其他单元。

### 受控导入工作进程强杀（真实隔离 MySQL）

run `593df06cca53097a` 在独立 socket-only MySQL target 上，以 `KillMode=control-group` 和 90 秒上限运行本轮专属导入测试单元。测试先记录工作单元的 InvocationID、主进程和 MySQL 客户端子进程身份，确认两者属于该单元控制组；再通过 InnoDB 事务信息观察到本轮 1000 条修改尚未提交、另一连接看到的订单数为 0。随后仅向该单元主进程发送 SIGKILL，核验主进程和已绑定的客户端子进程退出、控制组为空或已消失，确认对应活动事务消失且订单表仍为 0。独立只读判别返回 `MATCHES_BEFORE_BATCH` 且未改变账本；两个 MySQL 实例随后按身份停止，资源和状态保留。业务服务活动且 `ready=200`。

这是本轮已确认身份的**导入工作进程**在提交前被强杀，测试编排进程仍存活；不证明整机断电、跨重启、提交后强杀或一般情况下所有孤儿进程均能识别，也没有实现自动续传。重现入口 `baseline/isolated_mysql_supervised_kill_test.py` 的 SHA256 为 `9c216d4ae8e048d3a8da078057486605c025626059f9ab788c814afd1280349e`；它创建隔离 MySQL 和受时限控制的 root 测试单元，并强杀该单元主进程。只可在授权空闲 VM 中，先按前文要求放入 root 控制目录并独立核对摘要后运行。

## 应用服务和 Nginx 文件准备

`baseline/stack_files.py` 是基线部署的一个独立组件：默认 dry-run，核验 VMware 标记、目标路径、`devops`、项目应用文件和 Python 环境，规划三个固定版本文件 `/etc/systemd/system/orderguard-api.service`、`/etc/nginx/conf.d/00-orderguard-timing.conf` 和 `/etc/nginx/conf.d/orderguard.conf`。`--apply` 与凭据部署共用锁，仅以排他创建方式写入缺失文件；内容一致则跳过，存在冲突或不安全文件则拒绝，不覆盖。创建中途异常可能留下部分新文件和锁，保留现场并核对后重跑。

2026-11-13 在恢复副本的 root 控制暂存目录测试：3 项针对创建、重复检查、冲突、符号链接和并发创建的测试通过；dry-run 与一次 `--apply` 均显示三个文件 `same`，inode、权限、属主和内容摘要不变，现有服务活动且 `ready=200`。该环境不是干净 VM，因此尚未实测在干净 VM 创建配置并启动服务。

以 root 运行前，将 `stack_files.py` 和 `common.py` 暂存到 root 控制、祖先目录不可由普通用户修改的位置，独立核验 `stack_files.py` SHA256 `6e7fa2594f0c283ba076438637123fc72c37074e3a9f9932b09bf4dbea5a1855`、`common.py` SHA256 `de57fdab833d35ed3ebc042ce1327ffe642004e61e7bbf2ae5fffeeefa4755a4`。然后执行 `sudo python3 -I -B <受保护目录>/stack_files.py`，只有确认计划后才追加 `--apply`。脚本自身校验不能证明执行前未被篡改。

该组件不安装软件或依赖，不创建数据库、账号和凭据，不安装凭据 drop-in，不调整 SELinux，不执行 `daemon-reload`、`nginx -t`、启动或重载服务。应用源码必须已存在，且它由普通用户控制；运行该服务的信任边界见根 README。完整 `deploy → verify` 仍未实现。

## 应用数据库账号准备

`baseline/accounts.py` 默认只检查；`--apply` 仅在两个固定本地账号与两个凭据文件均不存在时创建。它要求已存在 root 保护的 `/etc/opsdrill/mysql-admin.cnf`、MySQL 本地 socket、旧库 5 条订单和影子库 500000 条订单。它按当前实验机权限模型配置 `orderguard_app` 对旧库的 SELECT/INSERT/UPDATE/DELETE，以及 `orderguard_stage3_reader` 仅对影子订单表的 SELECT；前者与现有权限一致，不宣称是针对每个当前 API 的最小权限。两个账号及凭据若已全部存在，仅在授权、认证和数据核对一致时标记 `same`；部分存在或不一致则保留并拒绝覆盖。

新密码由脚本生成，写入 root:root 0600 文件；SQL 通过本地 socket 的标准输入提交，登录核对通过内存文件描述符传递密码，不把密码放入命令行或输出。创建前要求 general log 和 log_raw 关闭、未发现活动审计插件/组件和复制配置；账号创建所在连接单独关闭 binlog，避免账号 DDL 进入该连接的 binlog。该检查不等同于证明不存在所有外部审计或抓取机制；应只在授权隔离实验机使用。MySQL DDL 隐式提交，任何失败都保留文件和账号现状供核查，不自动删除或盲目重试。

run `89592009facd7eb0` 在独立 socket-only MySQL 上使用 5 条旧订单和 1000 条合成影子订单，实测两账号新建、授权核对、密码认证和重复创建拒绝；测试将读账号期望数量限定为 1000，正式入口仍要求 500000。测试实例按身份停止、现场保留。现有业务库上 dry-run 和 `--apply` 均识别 `same`，凭据文件元数据及内容未改变，服务活动且 `ready=200`。另一次测试因凭据暂存路径未满足 root 祖先目录护栏而拒绝，隔离实例已按身份停止；不得把失败记录当作成功。4 项相关单元测试通过。

将 `accounts.py`、`common.py` 和 `verify` 复制到 root 控制、祖先目录不可由普通用户写入的位置，独立核对 SHA256：`accounts.py` `36cda599f164bce46eb4e75becf6efd2878cd1a8411c10c5bc8fb84b5a42240e`，`common.py` `de57fdab833d35ed3ebc042ce1327ffe642004e61e7bbf2ae5fffeeefa4755a4`，`verify` `440c4d5f98f1146c62c28725760430c66f371b0a5207b0bef8c6bb821d444df8`；从该受保护目录使用 `sudo python3 -I -B <受保护目录>/accounts.py` 预览，确认后才追加 `--apply`。依赖必须在执行前核验，程序自检不能替代来源审阅。重现实验 `baseline/isolated_mysql_accounts_test.py` 的 SHA256 为 `e4911ea329f8d9e3540d2c5119ce01d0083c37e15efb06c32602b7896dbf145a`，仅在授权空闲 VM、受保护暂存并核验后运行。

此组件不会安装 MySQL、创建管理员配置、导入数据、安装服务凭据 drop-in 或启动服务；干净 VM 的完整账号部署和整体 `deploy → verify` 尚未验证。参考：[MySQL 8.4 密码与日志](https://dev.mysql.com/doc/refman/8.4/en/password-logging.html)。

## MySQL 网络监听边界（2026-11-13）

检查恢复副本时发现 MySQL 的 3306 与 33060 原先监听所有地址；当时活动 public 防火墙区域未显式开放这两个端口，但这不等于服务本身只监听本机。已检查无活动 MySQL TCP 连接，备份现有 `/etc/my.cnf` 后追加 `bind-address=127.0.0.1` 和 `mysqlx-bind-address=127.0.0.1`，验证配置并重启实验 MySQL。之后两个端口均只监听 `127.0.0.1`，固定数据检查通过、订单服务 `ready=200`、SELinux Enforcing。原始配置和变更记录保存在 root 保护的 `/var/backups/opsdrill/Baseline/mysql-loopback-a0d8f56c7ae4564f`；其中的配置备份可能含敏感信息，不得公开。

新版 `baseline/verify` 额外检查 3306 必须由 mysqld 服务主进程监听回环地址，33060 若监听也必须为同一进程的回环地址；发现非回环监听为 FAIL，无法确认监听者为 UNKNOWN。此检查不代替防火墙规则审计，也不覆盖其他端口。32 项基线测试及恢复副本实际验证通过；`deploy` 和 `accounts.py` 的校验器固定摘要已同步更新，早期隔离账号测试仍使用其原本的受保护旧版候选。参考：[MySQL 8.4 服务端变量](https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html)、[MySQL 配置验证](https://dev.mysql.com/doc/refman/8.4/en/server-configuration-validation.html)。
