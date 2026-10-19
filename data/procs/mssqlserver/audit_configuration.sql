SELECT audit_key,audit_value FROM (
SELECT name AS audit_key,CASE WHEN value_in_use IS NULL THEN N'N' ELSE N'V'+CONVERT(NVARCHAR(MAX),value_in_use) END AS audit_value
FROM master.sys.configurations
WHERE name IN ('xp_cmdshell','clr enabled','Ole Automation Procedures','Ad Hoc Distributed Queries')
) audit_rows WHERE 1=1 ORDER BY audit_key
