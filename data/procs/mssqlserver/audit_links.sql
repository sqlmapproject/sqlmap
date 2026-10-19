SELECT audit_key,audit_value FROM (
SELECT N'visible linked servers' AS audit_key,N'V'+CONVERT(NVARCHAR(MAX),COUNT(*)) AS audit_value FROM master.sys.servers WHERE is_linked=1
UNION ALL
SELECT N'link '+CAST(name AS NVARCHAR(MAX)) COLLATE DATABASE_DEFAULT AS audit_key,N'V'+ISNULL(data_source COLLATE DATABASE_DEFAULT,N'<unknown>')+N' (data access: '+RTRIM(CASE is_data_access_enabled WHEN 1 THEN N'enabled' WHEN 0 THEN N'disabled' ELSE N'unavailable' END)+N'; RPC out: '+RTRIM(CASE is_rpc_out_enabled WHEN 1 THEN N'enabled' WHEN 0 THEN N'disabled' ELSE N'unavailable' END)+N')' AS audit_value
FROM master.sys.servers v WHERE is_linked=1 AND (SELECT COUNT(*) FROM master.sys.servers s WHERE s.is_linked=1 AND s.server_id<=v.server_id)<=%LIMIT%
) audit_rows WHERE 1=1 ORDER BY audit_key
