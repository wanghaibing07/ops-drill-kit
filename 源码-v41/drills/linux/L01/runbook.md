# Runbook L01：inode 与 deleted-open

## 范围和前提

仅在项目 VMware 实验机、实验标记和 `/mnt/opsdrill` 护栏通过后运行。控制器创建本轮私有 64 MiB ext4 镜像并校验镜像、loop 和挂载身份。先确认没有其他 L01 活动，保存 `start` 回执中的 `run_id`；deleted-open 变体还要保存回执中的专属 `unit`。

```bash
sudo bin/opsdrill status
sudo bin/opsdrill start L01 --variant inode
# 或：sudo bin/opsdrill start L01 --variant deleted-open
sudo bin/opsdrill check L01 --expect-run-id RUN_ID
```

有效故障的 check 返回 1，状态或环境错误返回 2。无活动演练时 check 不表示通过。

## 排查

根据本轮受控状态确定实验挂载点后执行：

```bash
df -hT MOUNT
df -i MOUNT
sudo du -xhd1 MOUNT
findmnt -T MOUNT
sudo lsof +L1
```

有可用磁盘块但空闲 inode 为零时，小文件也可能无法创建。`df` 统计文件系统已用空间，`du` 遍历目录项；已删除但仍被进程打开的文件可导致二者不一致。检查进程、文件描述符、实际挂载与本轮专属单元身份，不能只凭 PID 或 loop 编号操作。

## 受控恢复

inode 变体只清理确认属于本轮的空实验文件，恢复至少 10% 空闲 inode；不得递归删除未知目录。deleted-open 变体在确认持有者为本轮 transient systemd 服务后，停止该服务使句柄释放，不对未知进程发信号。应使用应用支持的 reopen/rotate/restart；对 `/proc/PID/fd/FD` 截断不是通用生产操作。

契约测试参考解法只用于验证：

```bash
sudo bash tests/solutions/L01/solution.sh inode RUN_ID
# deleted-open 变体：
sudo bash tests/solutions/L01/solution.sh deleted-open RUN_ID UNIT
sudo bin/opsdrill check L01 --expect-run-id RUN_ID
sudo bin/opsdrill reset L01 --expect-run-id RUN_ID
```

相同 ID 可重复 reset；若活动轮次已经改变则拒绝。身份不一致或未知资源存在时保留现场，不手动卸载未知设备或杀死未知进程。

## 日志轮转与验证

判题会校验实验机 `/etc/logrotate.d/nginx` 的权限、活动 Nginx 日志路径、保留策略和重开日志配置，并运行 logrotate 调试模式；它不实际轮转日志，也不证明定时器曾运行或 Nginx 已加载最新配置。检查通过后再确认无本轮挂载、镜像、loop 或 holder 残留。

`sudo bash tests/contract/l01.sh` 在两种变体上验证故障、受控恢复、检查和幂等复位；可用于项目复盘和展示。创建或清理中发生不可识别的中断时，控制器会拒绝自动清理，需先检查本轮现场。

## 官方参考

[lsof 手册：列出已解除链接但仍打开的文件](https://man7.org/linux/man-pages/man8/lsof.8.html)、[df 手册：文件系统可用空间](https://man7.org/linux/man-pages/man1/df.1.html)。
