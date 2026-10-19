SELECT audit_key,audit_value FROM (
SELECT name AS audit_key,CASE WHEN setting IS NULL THEN 'N' ELSE 'V'||setting END AS audit_value
FROM pg_catalog.pg_settings
WHERE name IN ('ssl','password_encryption','row_security','logging_collector','log_statement','log_connections','log_disconnections')
) audit_rows ORDER BY audit_key
