SELECT audit_key,audit_value FROM (
SELECT 'effective account' AS audit_key,CASE WHEN CURRENT_USER IS NULL THEN 'N' ELSE 'V'||CAST(CURRENT_USER AS TEXT) END AS audit_value
UNION ALL
SELECT 'login identity' AS audit_key,CASE WHEN SESSION_USER IS NULL THEN 'N' ELSE 'V'||CAST(SESSION_USER AS TEXT) END AS audit_value
UNION ALL
SELECT 'database' AS audit_key,CASE WHEN CURRENT_DATABASE() IS NULL THEN 'N' ELSE 'V'||CAST(CURRENT_DATABASE() AS TEXT) END AS audit_value
) audit_rows ORDER BY audit_key
