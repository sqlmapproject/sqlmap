SELECT audit_key,audit_value FROM (
SELECT 'secure_file_priv' AS audit_key,CASE WHEN @@GLOBAL.secure_file_priv IS NULL THEN 'N' ELSE CONCAT('V',CAST(@@GLOBAL.secure_file_priv AS CHAR)) END AS audit_value
UNION ALL
SELECT 'max_allowed_packet' AS audit_key,CASE WHEN @@GLOBAL.max_allowed_packet IS NULL THEN 'N' ELSE CONCAT('V',CAST(@@GLOBAL.max_allowed_packet AS CHAR)) END AS audit_value
) audit_rows ORDER BY audit_key
