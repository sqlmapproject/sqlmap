#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

class PRIORITY:
    LOWEST = -100
    LOWER = -50
    LOW = -10
    NORMAL = 0
    HIGH = 10
    HIGHER = 50
    HIGHEST = 100

class SORTORDER:
    FIRST = 0
    SECOND = 1
    THIRD = 2
    FOURTH = 3
    FIFTH = 4
    LAST = 100

class DBMS:
    ACCESS = "Microsoft Access"
    FIREBIRD = "Firebird"
    MAXDB = "SAP MaxDB"
    MSSQL = "Microsoft SQL Server"
    MYSQL = "MySQL"
    ORACLE = "Oracle"
    PGSQL = "PostgreSQL"
    SQLITE = "SQLite"
    SYBASE = "Sybase"

class OS:
    LINUX = "Linux"
    WINDOWS = "Windows"

class PLACE:
    GET = "GET"
    POST = "POST"
    SOAP = "SOAP"
    URI = "URI"
    COOKIE = "Cookie"
    UA = "User-Agent"
    REFERER = "Referer"

class HTTPMETHOD:
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"

class NULLCONNECTION:
    HEAD = "HEAD"
    RANGE = "Range"

class HASH:
    MYSQL = r'(?i)\A\*[0-9a-f]{40}\Z'
    MYSQL_OLD = r'(?i)\A[0-9a-f]{16}\Z'
    POSTGRES = r'(?i)\Amd5[0-9a-f]{32}\Z'
    MSSQL = r'(?i)\A0x0100[0-9a-f]{8}[0-9a-f]{40}\Z'
    MSSQL_OLD = r'(?i)\A0x0100[0-9a-f]{8}[0-9a-f]{80}\Z'
    ORACLE = r'(?i)\As:[0-9a-f]{60}\Z'
    ORACLE_OLD = r'(?i)\A[01-9a-f]{16}\Z'
    MD5_GENERIC = r'(?i)\A[0-9a-f]{32}\Z'
    SHA1_GENERIC = r'(?i)\A[0-9a-f]{40}\Z'
    CRYPT_GENERIC = r'(?i)\A[./0-9A-Za-z]{13}\Z'

# Reference: http://www.zytrax.com/tech/web/mobile_ids.html
class MOBILES:
    BLACKBERRY = "RIM Blackberry 9800 Torch;Mozilla/5.0 (BlackBerry; U; BlackBerry 9800; en-US) AppleWebKit/534.1+ (KHTML, like Gecko) Version/6.0.0.246 Mobile Safari/534.1+"
    GALAXY = "Samsung Galaxy S;Mozilla/5.0 (Linux; U; Android 2.2; en-US; SGH-T959D Build/FROYO) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1"
    HP = "HP iPAQ 6365;Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC; 240x320; HP iPAQ h6300)"
    HTC = "HTC Evo;Mozilla/5.0 (Linux; U; Android 2.2; en-us; Sprint APA9292KT Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1"
    IPHONE = "Apple iPhone 4;Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_0 like Mac OS X; en-us) AppleWebKit/532.9 (KHTML, like Gecko) Version/4.0.5 Mobile/8A293 Safari/531.22.7"
    NEXUS = "Google Nexus One;Mozilla/5.0 (Linux; U; Android 2.2; en-US; Nexus One Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1"
    NOKIA = "Nokia N97;Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 NokiaN97-1/10.0.012; Profile/MIDP-2.1 Configuration/CLDC-1.1; en-us) AppleWebKit/525 (KHTML, like Gecko) WicKed/7.1.12344"

class HTTPHEADER:
    ACCEPT_ENCODING = "Accept-Encoding"
    AUTHORIZATION = "Authorization"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    COOKIE = "Cookie"
    HOST = "Host"
    PROXY_AUTHORIZATION = "Proxy-authorization"
    RANGE = "Range"
    REFERER = "Referer"
    USER_AGENT = "User-Agent"

class WARNFLAGS:
    RANDOM_AGENT = 'randomAgent'
    DATA_TO_STDOUT = 'dataToStdout'
    THREADS = 'threads'
    TOR = 'tor'

class EXPECTED:
    BOOL = "bool"
    INT = "int"

class PAYLOAD:
    SQLINJECTION = {
                     1: "boolean-based blind",
                     2: "error-based",
                     3: "UNION query",
                     4: "stacked queries",
                     5: "AND/OR time-based blind"
                   }

    PARAMETER = {
                  1: "Unescaped numeric",
                  2: "Single quoted string",
                  3: "LIKE single quoted string",
                  4: "Double quoted string",
                  5: "LIKE double quoted string"
                }

    RISK = {
             0: "No risk",
             1: "Low risk",
             2: "Medium risk",
             3: "High risk"
           }

    CLAUSE = {
               0: "Always",
               1: "WHERE",
               2: "GROUP BY",
               3: "ORDER BY",
               4: "LIMIT",
               5: "OFFSET",
               6: "TOP",
               7: "Table name",
               8: "Column name"
             }

    class METHOD:
        COMPARISON = "comparison"
        GREP = "grep"
        TIME = "time"
        UNION = "union"

    class TECHNIQUE:
        BOOLEAN = 1
        ERROR = 2
        UNION = 3
        STACKED = 4
        TIME = 5

    class WHERE:
        ORIGINAL = 1
        NEGATIVE = 2
        REPLACE = 3
