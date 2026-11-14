# 证据文件索引

每条结论对应一个可核对的文件或一组事件，附指纹。在实验机上用 `sha256sum` 比对即可确认是不是同一次运行。

证据目录受 root 保护，路径只用于定位，不是下载链接。

## 容器与安装

| 结论 | 证据文件 | 指纹 |
|---|---|---|
| Rocky Linux 9.8 镜像校验一致 | 当日验收记录 | `d338032cd1cdd41c67139f2f71b4c832c8e4a21943106519db9c7137df7a63d4` |
| v41 安装候选包 | `ops-drill-kit-v1-安装候选-v41.zip` | `99a8b010cbee7cb32a7d27c6fdf3db76cec8c1bca303a14205a4637c4bd6e1c4` |

镜像大小为 2,755,067,904 字节，与本机记录和官方 CHECKSUM 三方一致。签名未验证——本机没有 gpg，这个缺口保留记录。

## 四个案例

| 结论 | 证据文件 | 指纹 |
|---|---|---|
| L02 端口拒绝、恢复、复位四段 | `/var/lib/opsdrill/events.jsonl` 批次 `L02-20261113-670451` | 四段事件各自留摘要，见案例文档 |
| L02 中断恢复（定时器自然触发） | 本轮事件与看门狗记录 | run `0ca533f01981bb1ec999bd7e` |
| N03 502 / 504 双变体 | `/var/backups/opsdrill/N03/gateway-evidence-018e9e687a49c41f/result.json` | `884ba89f338fc635c522028126b71c338493d4eae3477386d17098b214f8e9e9` |
| N03 首次 504 失败归档 | `/var/backups/opsdrill/N03/failed-start-archive-f96990034f868371/` | 失败事件保留，按原 run ID 复位 |
| M01 索引注入前基线 | `/opt/ops-drill-kit/evidence/m01-before-index.json` | `50832346a4680f6d9b98b2b8f4e92a82363946730ac4477cbcb66d77e2877f3c` |
| M01 索引恢复后基线 | `/opt/ops-drill-kit/evidence/m01-after-index.json` | `050d822c83dda1c9d50904ad72473850c12fd47590d4070b9e863dac6ed7f61e` |
| M01 分页对照 | 同目录 `m01-pagination-*.json`、`m01-pagination-plans.txt` | — |
| M04 应用直读恢复库 | `/var/backups/opsdrill/M04/app-db-live-4b8f863bade1383e/result.json` | `2cf3d6f8d381fa0be225136498863bcfea4873e4e6aa60dc9d4e187ca9acd57f` |
| M04 50 万行恢复目标联读 | `/var/tmp/opsdrill-m04-controller/9d8dd7878bb572db/app-business-result.json` | `c2ec466b7c06b489b9e38ef47e0797bedcac1311377d53b4e2d6b453aef54cdd` |
| M04 应用文件备份清单 | `/var/backups/opsdrill/M04/app-backup-restore-19d4d26e50c5b1dd/` | `f39ef951405b827e5a8d492acca7564b6ae491e511568c877e3250a1832c3590` |

## 其他演练

| 结论 | 证据文件 | 指纹 |
|---|---|---|
| M02 新机夹具死锁与两次复位 | `/var/tmp/opsdrill-m04-controller/5e5098fa2e31d07f/m02-fixture-result.json` | run `5e5098fa2e31d07f` |
| M02 隔离 CLI 快照 | `/var/tmp/opsdrill-m04-controller/f8e4e46a10396dbc/m02-fixture-result.json` | run `f8e4e46a10396dbc` |
| M03 连接耗尽生命周期 | `/var/backups/opsdrill/M03/lifecycle-7204775d3659352e4a99e99a` | run `7204775d3659352e4a99e99a` |
| M03 统一 CLI 契约 | `/var/backups/opsdrill/M03/` 下独立目录 | run `026363941790aebb4af5c899` |
| N02 网络配置前后对照 | `/var/backups/opsdrill/network-verification-fa3959f8c83831e5/N02.json` | 网卡、地址、路由、nft、sysctl 摘要一致 |
| N03 看门狗实测（502 / 504） | 同目录 `N03-502.json`、`N03-504.json` | 含 systemd invocation ID |
| N04 临时端口契约 | 本轮结果目录 | run `116784566a17d25ef54b18cf` |
| C01 有限窗口契约 | 有界判题输出 | run `a9cb8428bd4c8551f074b984` |

## 关键 run_id 速查

| 演练 | run_id | 说明 |
|---|---|---|
| L02 | `949c1b5837e9d7f934b51a26` | 首次，InvocationID 写入前注入，链路未闭合 |
| L02 | `0ca533f01981bb1ec999bd7e` | 定时器自然触发，链路闭合 |
| M04 | `8ea3dadb37fc948b` | 正常生命周期 |
| M04 | `a510094a3d511b7f` | v2 验证 |
| M04 | `96d9e068b81a00fb` | 停止意图落盘后、实际 stop 前中断 |
| M04 | `95817ee34f2987c8` | 应用文件 + 数据库同轮 |
| M04 | `8e1c0b8aab9a0587` | v3 暴露 unit 回收后无法核对身份 |
| M04 | `4a6cbe2782b24e0b` | v4 停止后、状态保存前中断，复位返回 STOPPED |
| M04 | `fd5303deba2c3d5a` | 单表 PITR，首次审计拒绝后续接 |
| M04 | `9d8dd7878bb572db` | 50 万行恢复目标应用联读 |

## 复核方法

```bash
# 独立结果文件
sudo sha256sum /path/to/result.json

# 共享事件文件里的单行（L02）
sudo sed -n '<行号>p' /var/lib/opsdrill/events.jsonl | tr -d '\n' | sha256sum
```

L02 的事件在共享 JSONL 里，必须按批次选行、去掉行末换行后单独计算，不能与整个文件的 `sha256sum` 混用。

不要从其他机器猜路径。不要公开原始日志——里面混着其他演练的记录和实验机的路径信息。
