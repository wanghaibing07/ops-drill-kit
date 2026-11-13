-- Read-only MySQL 8.4 diagnostic snapshot. Run with a protected option file.
-- Counts are snapshots, not a history or a diagnosis. No SQL text or credentials.
SELECT VERSION() AS mysql_version,
       @@GLOBAL.max_connections AS max_connections,
       @@GLOBAL.log_bin AS binlog_enabled,
       @@GLOBAL.binlog_format AS binlog_format,
       @@GLOBAL.binlog_row_image AS binlog_row_image;

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN ('Uptime', 'Threads_connected', 'Threads_running',
                        'Max_used_connections', 'Connection_errors_max_connections',
                        'Innodb_row_lock_current_waits', 'Slow_queries')
ORDER BY VARIABLE_NAME;

SELECT COUNT(*) AS active_innodb_transactions
FROM information_schema.innodb_trx;

SELECT COUNT(*) AS current_data_lock_waits
FROM performance_schema.data_lock_waits;

SELECT COALESCE(OBJECT_SCHEMA, '(none)') AS object_schema,
       COALESCE(OBJECT_NAME, '(none)') AS object_name,
       COUNT(*) AS waiting_lock_edges
FROM performance_schema.data_lock_waits w
JOIN performance_schema.data_locks l
  ON l.ENGINE = w.ENGINE AND l.ENGINE_LOCK_ID = w.REQUESTING_ENGINE_LOCK_ID
GROUP BY OBJECT_SCHEMA, OBJECT_NAME
ORDER BY waiting_lock_edges DESC, object_schema, object_name
LIMIT 20;
