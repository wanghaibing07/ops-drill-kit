# L03：受控 I/O 运行与恢复

适用范围：已启用项目 marker 的 VMware 实验机。实验目录与 MySQL 共用文件系统，单次负载限制为写入 64 MiB、读取不超过 256 MiB，并使用 systemd 30 秒硬超时及健康检查。

在项目根目录执行：

```bash
sudo bash drills/linux/L03/inject.sh
sudo bash drills/linux/L03/check.sh
sudo bash drills/linux/L03/reset.sh
sudo bash drills/linux/L03/check.sh
```

`inject` 输出本轮运行身份；运行中 `check` 可返回非零，完成后需检查状态与健康结果。`reset` 校验专属进程与文件身份后清理；状态或身份异常时保留资源，禁止手工扩大清理范围。两次 `reset` 应安全返回 `ALREADY_CLEAN`。

使用 `vmstat 1 3`、`iostat -xz 1 3` 和 `pidstat -d 1 3` 对照前、中、后样本；负载完成不等于磁盘瓶颈已复现。虚拟机时钟若未同步，墙上时间不能用于跨系统关联，持续时间使用单调时钟。实机原始输出留在受保护的实验机目录，提交仓库前需脱敏并核对。

本项目当前一次受控运行观察到单个 iostat 采样约 2.67% iowait，不能据此声称出现高 I/O wait；完整瓶颈复现仍待验证。

## 直接 I/O 候选及本次实测

当前工作负载以 256 KiB 同步块写入固定 64 MiB，并以 1 MiB 对齐缓冲直接读取四遍；不支持直接 I/O、短读或健康异常时失败，不主动退回缓存读。观察信息与工作负载成功分开：运行至少 2 秒、进程存储读取至少 64 MiB 且同期全系统 iowait 不低于 10% 时，才标记为系统 iowait 被观察到；这不是证明本轮负载是唯一原因。

run `144d827f0b0b20f679a26150` 实际写入 64 MiB、存储读取计数增加 256 MiB，耗时约 1.53 秒，全系统 iowait 8.51%，结论 `INCONCLUSIVE / WINDOW_TOO_SHORT`。业务健康和本轮身份清理通过，受保护原始采样与结果位于 `/var/tmp/opsdrill-l03-fasttrack.lYYTMXRb/`。这次没有证明高 I/O wait；若未来继续验证，应结合可对齐的基线、连续样本和设备指标判断，不夸大为瓶颈复现。

## 128 MiB 有界对照（2026-11-13）

独立候选 run `1b49cd9c5ef07621857ba1aa` 使用 128 MiB 写入、四遍直接读取；空闲三秒系统 iowait 为 0%，工作负载持续约 3.12 秒、读取计数增加 512 MiB，期间系统 iowait 平均 9.36%，未达到 10% 门槛。一次一秒设备采样显示 dm-0 读取约 372 MiB/s、对应 vmstat iowait 为 14%；这些采样与工作负载时间窗口并非严格同步，不能单独证明因果或持续瓶颈。受保护原始数据在 `/var/backups/opsdrill/L03/bounded-128-review-20261113`。本轮健康与身份绑定清理通过。

这是独立候选，当前正式 CLI 仍使用 64 MiB 控制器。不要把一次短时高采样或候选完成记为完整故障复现。

统一 CLI 的run `6ce55e9b8df54c002d12800e` 已核实负载完成、同一身份复位与报告 PARTIAL；该轮不证明持续高 iowait 或完整修复。`make contract-l03-controlled` 会在授权空闲实验机执行受控契约；完整证据与清理通过返回 0，证据不足时返回 2。旧命令 `make contract-l03-partial` 作为兼容别名保留。

## 官方参考

[vmstat 手册：CPU 与 I/O 统计](https://man7.org/linux/man-pages/man8/vmstat.8.html)、[proc_stat 手册：iowait 的局限](https://man7.org/linux/man-pages/man5/proc_stat.5.html)。

## 受控读取限速（2026-11-13）

控制器现在只对本轮 transient systemd 单元设置 `IOReadBandwidthMax=/mnt/opsdrill 32M`，不修改主机或其他服务的 I/O 策略。该限速人为制造等待，用于模拟受限吞吐；不能把它描述成磁盘硬件故障。实验仍只写 64 MiB、最多直接读 256 MiB，保留 30 秒硬时限与身份绑定清理。

隔离候选 run `990ca2ecc4612df78239de3f` 的空闲基线平均 iowait 为 0%，本轮约 9.33 秒内读取 256 MiB、平均系统 iowait 为 38.46%，身份绑定清理后 3 秒平均回到 0%；记录及设备采样保存在 `/var/backups/opsdrill/L03/bounded-portable-io-review-20261113`。这是一台实验机一次有界观察；全系统 iowait 不足以单独证明因果或真实磁盘故障。正式控制器已采用相同限速；受保护快照的统一 CLI run `1904bc02d49e4213b4151ae9` 验证工作负载和复位，该轮当时的 CLI 判题返回 PARTIAL，不能将当时的记录追认为完整自动验收。

## 同轮设备及 cgroup 补采（2026-11-13）

受保护 CLI 快照 run `6d528ef85a43b1a8a71b3d2c` 记录同一挂载设备 dm-0 的前、中、后共 18 次采样和本轮 cgroup 14 次样本。挂载设备经系统设备映射到本轮实际限速设备 259:0；cgroup `io.max` 显示 `rbps=32000000`，cgroup 采样中该设备读取计数增长，最大观察值为 260046848 字节。任务自身存储读取计数为 268435456 字节。两项采样窗口不同，不应要求它们数值相等或视作物理磁盘故障证明。

任务结束并按身份复位后，unit 已停止、readiness 为 200；执行前 readiness 也为 200，记录为健康维持，不虚构故障恢复。结构化原始采样在 `/var/backups/opsdrill/L03/controlled-contract-8683941f048de6f6/result.json`，SHA256 为 `be471d66d3f0a559bf82bba8049126a5343130237b08b2dd335b1b3b9dd201c5`。这是补充的受控观察；该轮当时的统一 CLI 自动检查和报告为 PARTIAL。

## 受控 I/O 自动判题（2026-11-13）

统一 CLI 新增范围明确的受控模拟判题。控制器在同一任务开始前和结束后记录挂载设备、底层限速设备、设备读取扇区、本轮 cgroup 读取字节、任务存储读取及健康状态；设备链、32 MB/s 限速和前后计数不完整或不一致时继续返回 PARTIAL。任务结束且证据通过时 `check` 返回 PASS，其含义仅为受控 I/O 模拟满足上述条件，不代表发现硬件故障，也不证明全系统 iowait 的唯一原因。

检查事件保存同一 run ID 和证据；CLI 复位通过并持久化状态目录删除后记录 CLEAN。报告只有看到有效的本轮检查证据以及后续 reset PASS、CLEAN 才显示受控模拟 PASS，否则仍为 PARTIAL；历史缺少证据的 PASS 不会被追认，不计算 L03 的完整故障 MTTR。

新机 root 保护候选快照run `39a0c0dc05fba64aece804fe` 完成受控负载、CLI 检查和复位，cgroup 读取增加 268435456 字节，挂载设备读取增加 524288 扇区；同一 attempt 事件保留、unit 停止、readiness 为 200。结果在 `/var/backups/opsdrill/l03-cli-proof-tests-d11f74ac5c10fc62/cli-contract-39a0c0dc05fba64aece804fe.json`，SHA256 `e4d10ca8c4767073bd6790c73a0963a442d20d13ac25a58648ce6c048911bad3`。候选完整 Python 单元测试 200 项通过；自动运行标记 `actor=agent`。

受保护快照的新契约 run `cadef84b2e5b35e1f4d9f4e0` 实际完成注入、检查、身份绑定复位和报告核对，退出 0；该结果仅表示受控 I/O 模拟闭环。证据不全仍返回 2。
