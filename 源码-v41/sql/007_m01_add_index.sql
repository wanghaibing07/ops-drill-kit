USE orderguard_stage3;
SET SESSION lock_wait_timeout = 10;
ALTER TABLE orders ADD INDEX idx_merchant_status_created (merchant_id, order_status, created_at), ALGORITHM=INPLACE, LOCK=NONE;
