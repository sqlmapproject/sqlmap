SELECT audit_key,audit_value FROM (
SELECT 'execute xp_cmdshell' AS audit_key,CASE WHEN HAS_PERMS_BY_NAME('master.dbo.xp_cmdshell','OBJECT','EXECUTE') IS NULL THEN N'N' ELSE N'V'+CONVERT(NVARCHAR(MAX),HAS_PERMS_BY_NAME('master.dbo.xp_cmdshell','OBJECT','EXECUTE')) END AS audit_value
UNION ALL
SELECT 'read configuration metadata' AS audit_key,CASE WHEN HAS_PERMS_BY_NAME('master.sys.configurations','OBJECT','SELECT') IS NULL THEN N'N' ELSE N'V'+CONVERT(NVARCHAR(MAX),HAS_PERMS_BY_NAME('master.sys.configurations','OBJECT','SELECT')) END AS audit_value
UNION ALL
SELECT 'read linked-server metadata' AS audit_key,CASE WHEN HAS_PERMS_BY_NAME('master.sys.servers','OBJECT','SELECT') IS NULL THEN N'N' ELSE N'V'+CONVERT(NVARCHAR(MAX),HAS_PERMS_BY_NAME('master.sys.servers','OBJECT','SELECT')) END AS audit_value
) audit_rows WHERE 1=1 ORDER BY audit_key
