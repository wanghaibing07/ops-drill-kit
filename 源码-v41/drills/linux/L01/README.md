# L01 磁盘演练原型

状态：两个变体的统一 CLI 基础契约已在实验机通过；自动结果标记为 `actor=agent`。它们使用独立私有 64 MiB ext4 loop 镜像，分别复现 inode 耗尽和 deleted-open 文件句柄。

```bash
sudo bin/opsdrill start L01 --variant inode
sudo bin/opsdrill check L01
sudo bin/opsdrill reset L01
```

将 `inode` 换成 `deleted-open` 可选择另一变体。两种变体的 reset 均绑定本轮运行身份；修复前 check 返回非零。

仅在项目 VMware 实验机、由 root 执行，并先确认没有其他 L01 操作。控制器检查实验标记、路径、镜像及 loop 身份后才会操作。inode 候选入口：

```bash
sudo python3 drills/linux/L01/l01_control.py inject
sudo python3 drills/linux/L01/l01_control.py check
sudo python3 drills/linux/L01/l01_control.py reset
```

故障存在时 check 返回 1；空闲 inode 至少 10%、文件系统可写且日志轮转配置验证通过时返回 0。reset 卸载并删除本轮已验证的私有镜像，重复 reset 可用。异常或身份不一致时拒绝操作，保留现场供检查；并非所有创建和删除中的中断都能自动恢复。

deleted-open 变体使用独立目录和专属临时 systemd 服务，服务最多运行 30 分钟：

```bash
sudo python3 drills/linux/L01/l01_deleted.py inject
sudo python3 drills/linux/L01/l01_deleted.py check
# 确认 inject 输出的服务属于本轮后，以该服务名为参数执行 systemctl stop。
sudo python3 drills/linux/L01/l01_deleted.py check
sudo python3 drills/linux/L01/l01_deleted.py reset
```

已删除文件仍有打开句柄时 check 返回 1；句柄全部释放、inode 空闲至少 10%、文件系统可写且日志轮转配置验证通过时返回 0。reset 只停止经身份核验的本轮服务。启动结果不明等部分中断状态会拒绝自动清理，需要检查现场。

轮转判题针对本实验机的 `/etc/logrotate.d/nginx`：检查文件权限、Nginx 当前配置文件中的 OrderGuard 日志路径、保留策略和重开日志配置，并以 logrotate 调试模式验证语法及覆盖范围。调试模式不执行轮转；此检查不证明 Nginx 已加载最新配置、定时器已触发或实际轮转成功。配置采用不同形式时需调整判题，不能据此断言不存在轮转策略。

`tests/contract/l01.sh` 覆盖两个变体的故障、受控恢复、判题、错误运行 ID 拒绝和重复复位；`tests/contract/l01_failures.py` 覆盖格式化前、挂载前、创建文件中断及专属持有服务启动后中断，验证受控回滚和宿主挂载、loop 清单不变。它们不代表任意时刻强杀、重启或设备身份交换均已实测；身份不明时保留现场并拒绝危险清理。工单、提示、runbook 和复盘模板位于本目录；自动执行可作为项目实操记录；执行者标记和个人操作计时均保持真实。
