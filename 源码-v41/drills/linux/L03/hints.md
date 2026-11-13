# 提示

1. 用 `vmstat 1 3` 区分 CPU 忙和等待 I/O 的时间。
2. 用 `iostat -xz 1 3` 和 `pidstat -d 1 3` 查设备及进程 I/O。
3. 检查 `/health`、`/ready` 及服务状态；对照 `check.sh` 的实际输出。
4. 只清理 L03 标识确认的资源，身份不明时保留并排查。
