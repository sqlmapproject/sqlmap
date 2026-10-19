SELECT audit_key,audit_value FROM (
SELECT name AS audit_key,CASE WHEN value IS NULL THEN 'N' ELSE 'V'||value END AS audit_value
FROM v$parameter
WHERE name IN ('remote_os_authent','remote_login_passwordfile','sql92_security','audit_trail','os_authent_prefix')
) audit_rows ORDER BY audit_key
