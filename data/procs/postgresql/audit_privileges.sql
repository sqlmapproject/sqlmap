SELECT audit_key,audit_value FROM (
SELECT 'superuser' AS audit_key,'V'||CASE WHEN rolsuper THEN '1' ELSE '0' END AS audit_value FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER
UNION ALL
SELECT 'bypass RLS','V'||CASE WHEN rolbypassrls THEN '1' ELSE '0' END FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER
UNION ALL
SELECT rolname,'V'||CASE WHEN pg_has_role(oid,'USAGE') THEN '1' ELSE '0' END FROM pg_catalog.pg_roles WHERE rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program')
) audit_rows ORDER BY audit_key
