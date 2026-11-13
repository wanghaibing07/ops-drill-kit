USE orderguard;
INSERT IGNORE INTO merchants (id, name) VALUES (1, 'Demo Store A'), (2, 'Demo Store B');
INSERT IGNORE INTO orders (id, merchant_id, amount, status) VALUES (1001, 1, 99.00, 'paid'), (1002, 1, 199.50, 'pending'), (1003, 1, 49.90, 'paid'), (1004, 2, 299.00, 'cancelled'), (1005, 2, 88.80, 'paid');
