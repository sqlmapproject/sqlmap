EXEC master..sp_configure 'show advanced options',1;
RECONFIGURE WITH OVERRIDE;
EXEC master..sp_configure 'ole automation procedures',1;
RECONFIGURE WITH OVERRIDE
