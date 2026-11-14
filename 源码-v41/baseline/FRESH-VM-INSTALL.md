# 独立实验 VM 安装入口（候选）

此入口面向独立的 Rocky Linux 9 VMware 实验 VM，不创建 VM，也不会覆盖已有项目、实验目录或初始化账本。目标需提前有 `devops`、公钥 SSH 登录和免交互 sudo；宿主机需有 Python 3 和 Paramiko。原 VM、快照和旧锁不要作为安装目标。

准备以下参数：目标 VMX 绝对路径、`vmrun.exe` 路径、目标私网 IP、独立核实的 DMI UUID 和 SSH Ed25519 公钥指纹、现有私钥文件路径、载荷目录，以及从可信渠道取得的 `source.tar.gz`、`extract.py`、`stage.py` 和 `baseline/bootstrap.py` SHA256。不要把私钥或密码放入载荷、源码或日志。主机入口是 `baseline/fresh_vm_transport.py`，运行 `python -X utf8 -B baseline/fresh_vm_transport.py --help` 查看参数。

使用相同的身份和摘要参数，按顺序执行 `inspect`、`upload`、`stage-dry-run --inbox <upload 返回的目录>`、`stage-apply --inbox <同一目录>`、`bootstrap-dry-run`，确认前置条件后执行 `bootstrap-apply`。阶段与动作顺序以 `--help` 显示为准，所有动作中的 `--inbox` 是本次新建的专属目录。安装步骤标记 `actor=agent`；真实用户练习须另行记录。

传输入口验证运行中的 VMX、预期 UUID、SSH 主机公钥及载荷摘要；目标端再次校验 DMI、root 保护路径和清单。安装失败、目标已存在、身份不一致或结果不明时保留现场，不自动重试。`bootstrap-apply` 会安装系统包、初始化 MySQL 和导入合成订单；不得对现有业务库执行。载荷解包、v3 安装和阶段顺序已做隔离验证，但修复后的完整干净机 apply **尚未实测通过**；不要把候选入口描述成已完成的端到端验收。

2026-11-13：候选 bootstrap 已加入 12 个固定摘要的演练控制器安装步骤，并补充 M02 所需的 Python 3.11 系统 RPM。新机曾因缺少这些 RPM 停在 M02 安装；依赖补齐后，12 个控制器以独立账本受控续接安装，所有清单和 CLI 命令构造通过校验。此结果不是完整干净 bootstrap 的无干预通过。

M02 基线按版本隔离：旧控制器严格检查 3/3，新机固定种子使用 `baseline-v2` 严格检查 2/3。新机已安装两套控制器，并以 v2 初始化专用写账号、核验认证和列级权限；订单状态保持 2/3。新机演练入口需显式指定 `--m02-version baseline-v2`；既有未标版本的历史运行仍走旧控制器。v2 已在新机独立 socket-only 合成夹具内验证真实死锁、检查和两次复位；正常统一 CLI 端到端契约尚未实测，不能混为一谈。


隔离 CLI 快照 run `f8e4e46a10396dbc` 使用为隔离夹具适配路径及摘要清单的 CLI、launcher 和 v2 控制器，验证启动、检查、复位、重复检查与复位，错误 run ID 被拒绝。独立复核死锁证据摘要、4 条 `actor=agent` 事件、临时实例停止及夹具凭据删除，业务 readiness 为 200。结果在 `/var/tmp/opsdrill-m04-controller/f8e4e46a10396dbc/m02-fixture-result.json`。这不等于新机未修改的普通 CLI 完整实机契约通过。


新机另一次run `96d88e2a43d1d6fb` 使用与交付包相同摘要的原样 CLI 和已安装的原样 v2 控制器，在私有挂载命名空间映射隔离配置、状态及证据目录，连接独立 socket-only 合成数据库。启动、检查、复位、重复检查和复位通过，错误 ID 被拒绝；死锁证据摘要、4 条事件、实例停机和临时凭据删除均独立复核。结果在 `/var/tmp/opsdrill-m04-controller/96d88e2a43d1d6fb/m02-fixture-result.json`。该测试不代表普通宿主机配置的完整端到端契约。事件记录仅有 attempt ID；run ID 与版本保存在独立运行结果及状态证据中，不能声称事件自身包含完整关联。此前 run `d2334722d6b1db63` 因隔离状态目录缺失在注入前失败，保留失败账本，并使用独立受控续接记录完成临时资源清理。
