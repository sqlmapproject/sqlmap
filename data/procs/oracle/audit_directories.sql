SELECT audit_key,audit_value FROM (
SELECT 'visible directory grants' AS audit_key,'V'||TO_CHAR(COUNT(*)) AS audit_value
FROM all_directories d JOIN all_tab_privs p ON p.table_schema=d.owner AND p.table_name=d.directory_name
WHERE p.type='DIRECTORY' AND p.privilege IN ('READ','WRITE') AND (p.grantee=SYS_CONTEXT('USERENV','CURRENT_USER') OR p.grantee='PUBLIC' OR p.grantee IN (SELECT role FROM session_roles))
UNION ALL
SELECT audit_key,audit_value FROM (
SELECT d.directory_name||' ['||p.privilege||'] (via '||p.grantee||')' AS audit_key,'V'||d.directory_path AS audit_value
FROM all_directories d JOIN all_tab_privs p ON p.table_schema=d.owner AND p.table_name=d.directory_name
WHERE p.type='DIRECTORY' AND p.privilege IN ('READ','WRITE') AND (p.grantee=SYS_CONTEXT('USERENV','CURRENT_USER') OR p.grantee='PUBLIC' OR p.grantee IN (SELECT role FROM session_roles))
ORDER BY d.directory_name,p.privilege,p.grantee
) audit_details WHERE ROWNUM<=%LIMIT%
) audit_rows ORDER BY audit_key
