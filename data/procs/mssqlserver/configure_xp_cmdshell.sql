EXEC master..sp_configure 'show advanced options',1;
RECONFIGURE WITH OVERRIDE;
EXEC master..sp_configure 'xp_cmdshell',%ENABLE%;
RECONFIGURE WITH OVERRIDE;
EXEC master..sp_configure 'show advanced options',0;
RECONFIGURE WITH OVERRIDE
