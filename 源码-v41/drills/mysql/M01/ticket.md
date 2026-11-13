# M01 工单

商户 88 的订单查询在索引失效后变慢。限定于 VMware 中的 `orderguard_stage3.orders`。

任务：在不修改业务数据、旧库、API 和全局日志设置的前提下，定位联合索引是否对优化器可见，恢复查询计划，执行判题并复位。

核心 SQL：`merchant_id=88 AND order_status=1 AND created_at >= '2026-10-01 00:00:00' ORDER BY created_at DESC LIMIT 20`。
