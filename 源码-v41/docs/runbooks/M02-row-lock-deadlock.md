# Runbook：M02 MySQL 行锁等待与死锁

- Drill ID：M02
- Version：1.0
- Status：Draft，待本人复核
- Environment：Rocky Linux 9.8 / MySQL 8.4.13
- Project：ops-drill-kit / OrderGuard
- Database：orderguard_stage3
- Table：orders
- Target records：10086、10087
- Git baseline：39ca2f7

## 1. Symptoms and impact

模拟订单状态更新出现以下现象：

- SQL 执行长时间等待。
- MySQL 返回 Lock wait timeout exceeded。
- MySQL 返回 Deadlock found when trying to get lock。
- API 数据库操作出现延迟或失败。

影响范围限定为实验虚拟机内的合成订单数据。

不代表真实客户生产故障，不涉及真实交易数据。

## 2. Scope and assumptions

### 实验对象

只允许操作：

- Database：orderguard_stage3
- Table：orders
- Primary Key：10086、10087
- Initial order_status：两条均为 3

### 账号边界

- Writer：orderguard_m02_writer
- Observer：使用现有受保护管理员连接配置。
- Writer 仅具有指定列的 SELECT、UPDATE 权限。
- 不使用数据库 root 作为业务 Writer。

密码不得进入命令参数、终端输出、源码、日志、证据或 Git。

### 全局配置基线

| 参数                       | 已验证基线 |
| ------------------------ | ----- |
| log_bin                  | 1     |
| innodb_deadlock_detect   | 1     |
| innodb_lock_wait_timeout | 50    |

实验仅允许在 SESSION 范围设置超时，不修改上述全局设置。

## 3. First 60 seconds

1. 确认当前虚拟机和项目标记。
2. 确认 MySQL、API、Nginx 服务状态。
3. 确认 `/ready` 正常。
4. 确认目标订单状态。
5. 检查当前活动事务和锁等待。
6. 识别等待方、阻塞方、连接 ID 和线程 ID。

禁止未经确认直接 KILL 阻塞事务。

## 4. Diagnostic commands

### 服务检查

```
```bash
systemctl is-active mysqld orderguard-api nginx
curl --fail --silent --show-error http://127.0.0.1:8080/ready
```
```

### 数据库基线

```
```sql
SELECT id, order_status
FROM orderguard_stage3.orders
WHERE id IN (10086,10087)
ORDER BY id;
```
```

### 等待关系

优先使用：

- performance_schema.data_lock_waits
- performance_schema.data_locks
- performance_schema.threads
- performance_schema.events_transactions_current

关联检查必须确认：

- REQUESTING_THREAD_ID
- BLOCKING_THREAD_ID
- ENGINE_TRANSACTION_ID
- OBJECT_SCHEMA
- OBJECT_NAME
- INDEX_NAME
- LOCK_TYPE
- LOCK_MODE
- LOCK_STATUS
- LOCK_DATA

只检查本次实验的连接、线程、目标表和目标记录。

不保存其他会话的 SQL 文本。

### INNODB_TRX 注意事项

INFORMATION_SCHEMA.INNODB_TRX 与 Performance Schema 锁视图之间可能存在短暂观测不一致。

不得仅凭单次 INNODB_TRX 查询结果判断事务是否仍持锁。

恢复检查结合：

- ROLLBACK 返回结果
- P_S 线程
- P_S 目标锁
- P_S 等待关系
- INNODB_TRX
- 实际订单状态

### 已实现演练入口

在项目目录运行。先检查状态；不同演练共用互斥锁，不要并行执行。

```bash
bash scripts/m02_deadlock.sh status
bash scripts/m02_deadlock.sh inject
bash scripts/m02_deadlock.sh check
bash scripts/m02_deadlock.sh reset
sudo .venv/bin/python scripts/m02_retry_controller.py
sudo .venv/bin/python scripts/m02_retry_controller.py recover
sudo bash scripts/m02_ordered_pair.sh
sudo bash scripts/m02_ordered_pair.sh recover
```

M02 死锁入口现在由非 root wrapper 转发到 root 独立安装的控制器；不要用 sudo 执行项目内可写 wrapper。以 root 直接操作时使用固定安装的 launcher。执行前分别阅读 `README-M02-DEADLOCK.md`、`README-M02-RETRY.md` 和 `README-M02-ORDERED-PAIR.md` 中的前置条件及异常恢复步骤。A 的原始手工实验没有单独的版本化 JSON 证据；不要把后续死锁文件冒充 A 的证据。

## 5. Decision tree

### A. 普通行锁等待

判断：

- 是否存在真实等待边。
- 哪个事务持有目标锁。
- 哪个事务请求目标锁。
- 阻塞事务是否仍在执行。

恢复：

1. 确认阻塞事务归属。
2. 在实验环境中由事务持有者显式 ROLLBACK。
3. 验证等待事务是否继续执行。
4. 验证双方最终事务状态。

### B. 死锁 1213

判断：

- 是否存在循环等待。
- 是否存在相反的锁获取顺序。
- MySQL 实际选择了哪个 Victim。

恢复：

1. 识别 1213。
2. 确认受害事务已经回滚。
3. 确认存活事务的状态。
4. 两个实验连接均显式 ROLLBACK。
5. 验证目标数据恢复。

### C. 锁等待超时 1205

判断：

- 阻塞方是否仍持有目标锁。
- 等待方此前是否已经持有其他记录锁。
- 是否已经发生真实 1205。

恢复：

1. 等待方显式 ROLLBACK 整笔事务。
2. 验证其此前取得的锁已经释放。
3. 验证相关事务及等待均消失。
4. 释放阻塞方。
5. 使用新连接从事务第一步重新执行。
6. 成功后按实验要求 ROLLBACK。

不能只重试发生错误的 UPDATE。

## 6. Mitigation

实验环境：

- 使用受控 ROLLBACK 释放事务。
- 不使用 KILL 代替正常事务清理。
- 需要重试时重新建立连接。
- 1213、1205 采用整笔事务重试。
- 设置最大重试次数和有界退避。
- 不允许无限重试。

实际业务系统：

- 统一多行锁获取顺序。
- 缩短事务持锁时间。
- 避免事务中执行不必要的网络请求。
- 为可重试业务设计幂等机制。
- 对事务之外的副作用使用可靠的幂等或消息交付机制。

## 7. Permanent fix

本项目采用：

统一锁顺序：

10086 → 10087

事务重试：

- 仅对明确允许重试的错误进行重试。
- 1213：整个事务重新执行。
- 1205：应用显式回滚整个事务后重新执行。
- 最大重试次数：3。
- 使用有界指数退避和随机抖动。

## 8. Verification

最终验收条件：

| 检查项                  | 预期       |
| -------------------- | -------- |
| 10086 order_status   | 3        |
| 10087 order_status   | 3        |
| 活动事务                 | 0        |
| 活动锁等待                | 0        |
| A/B 目标锁              | 0        |
| A/B 线程               | 已退出      |
| log_bin              | 1        |
| 全局 lock_wait_timeout | 50       |
| /ready               | HTTP 200 |

C1、C2 的恢复检查使用 200ms 采样并要求连续两次干净观察；具体记录以各证据文件为准。

恢复窗口不得通过无限延长超时来掩盖异常。

## 9. Rollback and reset

- 只允许复位本项目创建的状态文件和实验对象。
- ROLLBACK 必须有明确结果。
- recover 必须验证状态元数据、数据库实例、全局配置和恢复状态。
- 底层 reset 验证恢复后保留受保护的完成状态；新一轮开始时才会替换该记录。
- needs-recovery 状态禁止重复 inject。
- 不修改旧业务数据库 orderguard。
- 不删除 base-clean 或 stack-ok 快照。

## 10. Evidence

保留：

- M02-A 原始手工实验缺少独立版本化 JSON；相关观察见实验记录，待补可追溯证据。
- M02-B 真实 1213 证据。
- M02-C1 真实 1205 和完整事务重试证据。
- M02-C2 双事务统一加锁顺序证据。
- 失败尝试的脱敏状态。
- 单元测试及 Bats 结果。
- Git commit 和 SHA256。

不得提交密码、原始敏感 SQL 或完整数据库备份。

## 11. Limitations

- 单台 VMware 虚拟机。
- 合成订单数据。
- 非真实生产环境。
- 未形成真实客户 SLA。
- 1213 整笔重试的自动化集成实测仍待补充。
- 用户本人 MTTD、MTTR 练习记录待填写。

## 12. Version / reproduction date / references

- Rocky Linux：9.8
- MySQL：8.4.13
- M02-C2 commit：39ca2f7
- C2 evidence：evidence/m02-ordered-pair-20261110T194256.330642Z.json

官方参考：

- [https://dev.mysql.com/doc/refman/8.4/en/innodb-deadlocks.html](https://dev.mysql.com/doc/refman/8.4/en/innodb-deadlocks.html)
- [https://dev.mysql.com/doc/refman/8.4/en/innodb-error-handling.html](https://dev.mysql.com/doc/refman/8.4/en/innodb-error-handling.html)
- [https://dev.mysql.com/doc/refman/8.4/en/performance-schema-data-locks-table.html](https://dev.mysql.com/doc/refman/8.4/en/performance-schema-data-locks-table.html)
- [https://dev.mysql.com/doc/refman/8.4/en/performance-schema-data-lock-waits-table.html](https://dev.mysql.com/doc/refman/8.4/en/performance-schema-data-lock-waits-table.html)
