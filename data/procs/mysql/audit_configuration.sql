SELECT audit_key,audit_value FROM (
SELECT LOWER(VARIABLE_NAME) AS audit_key,CASE WHEN VARIABLE_VALUE IS NULL THEN 'N' ELSE CONCAT('V',VARIABLE_VALUE) END AS audit_value
FROM performance_schema.global_variables
WHERE LOWER(VARIABLE_NAME) IN ('local_infile','require_secure_transport','read_only','super_read_only','general_log','log_bin','skip_networking','skip_grant_tables')
) audit_rows ORDER BY audit_key
