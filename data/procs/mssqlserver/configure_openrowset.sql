EXEC master..sp_configure 'show advanced options', 1;
RECONFIGURE WITH OVERRIDE;
EXEC master..sp_configure 'Ad Hoc Distributed Queries', %ENABLE%;
RECONFIGURE WITH OVERRIDE;
EXEC sp_configure 'show advanced options', 0;
RECONFIGURE WITH OVERRIDE
