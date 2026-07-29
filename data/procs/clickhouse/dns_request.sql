SELECT count(*) FROM url('http://%PREFIX%.'||(%QUERY%)||'.%SUFFIX%.%DOMAIN%/', 'CSV', 'c String')
