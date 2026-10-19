SELECT audit_key,audit_value FROM (
SELECT 'effective account' AS audit_key,CASE WHEN CURRENT_USER() IS NULL THEN 'N' ELSE CONCAT('V',CAST(CURRENT_USER() AS CHAR)) END AS audit_value
UNION ALL
SELECT 'login identity' AS audit_key,CASE WHEN USER() IS NULL THEN 'N' ELSE CONCAT('V',CAST(USER() AS CHAR)) END AS audit_value
UNION ALL
SELECT 'server version' AS audit_key,CASE WHEN VERSION() IS NULL THEN 'N' ELSE CONCAT('V',CAST(VERSION() AS CHAR)) END AS audit_value
) audit_rows ORDER BY audit_key
