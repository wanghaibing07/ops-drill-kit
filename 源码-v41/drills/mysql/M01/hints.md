# M01 诊断提示

1. `SHOW INDEX FROM orderguard_stage3.orders;` 检查 `Visible`。
2. `EXPLAIN` 固定 SQL，检查 `key` 是否从 `idx_merchant_status_created` 退回其他索引。
3. MySQL 8.4 支持 `ALTER TABLE ... ALTER INDEX ... VISIBLE`，无需 DROP/RECREATE。
