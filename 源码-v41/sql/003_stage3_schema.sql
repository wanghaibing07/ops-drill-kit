CREATE DATABASE orderguard_stage3
CHARACTER SET utf8mb4
COLLATE utf8mb4_0900_ai_ci;

USE orderguard_stage3;

CREATE TABLE merchants (
    merchant_id INT UNSIGNED NOT NULL,
    merchant_name VARCHAR(64) NOT NULL,
    region VARCHAR(32) NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (merchant_id)
) ENGINE=InnoDB;

INSERT INTO merchants (
    merchant_id,
    merchant_name,
    region,
    created_at
)
WITH RECURSIVE seq AS (
    SELECT 1 AS n
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 500
)
SELECT
    n,
    CONCAT('synthetic-merchant-', LPAD(n, 4, '0')),
    ELT(
        1 + MOD(n - 1, 5),
        'shenzhen',
        'guangzhou',
        'dongguan',
        'foshan',
        'zhuhai'
    ),
    '2026-01-01 00:00:00'
FROM seq;

CREATE TABLE orders (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    order_no VARCHAR(32) NOT NULL,
    merchant_id INT UNSIGNED NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    order_status TINYINT UNSIGNED NOT NULL,
    amount_cents INT UNSIGNED NOT NULL,
    pay_channel VARCHAR(16) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_order_no (order_no),
    KEY idx_orders_merchant_id (merchant_id),

    CONSTRAINT fk_stage3_orders_merchant
        FOREIGN KEY (merchant_id)
        REFERENCES merchants(merchant_id)
        ON DELETE RESTRICT,

    CONSTRAINT chk_stage3_order_status
        CHECK (order_status BETWEEN 0 AND 4),

    CONSTRAINT chk_stage3_amount
        CHECK (amount_cents BETWEEN 100 AND 99900)
) ENGINE=InnoDB;
