SELECT audit_key,audit_value FROM (
SELECT 'DBA role active' AS audit_key,'V'||CASE WHEN COUNT(*)>0 THEN 'yes' ELSE 'no' END AS audit_value FROM session_roles WHERE role='DBA'
UNION ALL
SELECT privilege,'Vgranted' FROM session_privs WHERE privilege IN ('CREATE ANY DIRECTORY','CREATE EXTERNAL JOB','EXECUTE ANY PROCEDURE','ALTER SYSTEM','SELECT ANY DICTIONARY')
) audit_rows ORDER BY audit_key
