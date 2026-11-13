CREATE TABLE orderguard_stage3.legacy_merchants LIKE orderguard.merchants;
CREATE TABLE orderguard_stage3.legacy_orders LIKE orderguard.orders;
ALTER TABLE orderguard_stage3.legacy_orders
    ADD CONSTRAINT fk_legacy_orders_merchant FOREIGN KEY (merchant_id)
    REFERENCES orderguard_stage3.legacy_merchants(id) ON DELETE RESTRICT;
