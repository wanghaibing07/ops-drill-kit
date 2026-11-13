# M01 统一入口与自动恢复

该入口只切换 `orderguard_stage3.orders.idx_merchant_status_created` 的可见性，不修改 MySQL 全局参数。启动时记录本轮 run ID 和配置基线，先安装 180 秒 watchdog，再将索引设为 INVISIBLE；判题检查真实执行计划。修复恢复 VISIBLE，最后 reset 清理本轮状态。

首次使用前审阅 `scripts/install_m01.py` 和本目录的受保护控制器模块，将审阅后的安装器放到仅 root 可修改的位置，再以 root 执行安装器并传入本目录。安装器校验固定摘要，不覆盖不同版本或不安全路径。

```bash
sudo bin/opsdrill start M01 --actor unknown
sudo bin/opsdrill check M01 --expect-run-id RUN_ID --actor unknown
sudo bash tests/solutions/M01/owned_solution.sh RUN_ID
sudo bin/opsdrill check M01 --expect-run-id RUN_ID --actor unknown
sudo bin/opsdrill reset M01 --expect-run-id RUN_ID --actor unknown
```

watchdog 只恢复本轮索引可见性并保留状态，仍需 reset。持锁超过看门狗等待上限、身份或数据库基线变化时会拒绝操作；虚拟机重启后，可在确认本轮状态及索引身份后使用同一 run ID 执行 reset。数据库管理员的非协作 DDL 不受项目锁约束，应在独占实验环境中运行。

2026-11-12 在 Rocky Linux 隔离恢复副本中完成了按运行 ID 的故障、修复和重复复位；最终统一 CLI 控制器的 180 秒 watchdog 恢复和复位也已实测；重启后的保守 reset 路径有模拟测试，尚未通过重启虚拟机实测。原始执行者标记和局限保持真实；自动执行属于该 AI 协作项目的实操记录，不代表项目全部验收已完成。
