#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
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

class SORT_ORDER:
    FIRST = 0
    SECOND = 1
    THIRD = 2
    FOURTH = 3
    FIFTH = 4
    LAST = 100

class DBMS:
    ACCESS = "Microsoft Access"
    DB2 = "IBM DB2"    
    FIREBIRD = "Firebird"
    MAXDB = "SAP MaxDB"
    MSSQL = "Microsoft SQL Server"
    MYSQL = "MySQL"
    ORACLE = "Oracle"
    PGSQL = "PostgreSQL"
    SQLITE = "SQLite"
    SYBASE = "Sybase"

class DBMS_DIRECTORY_NAME:
    ACCESS = "access"
    DB2 = "db2"
    FIREBIRD = "firebird"
    MAXDB = "maxdb"
    MSSQL = "mssqlserver"
    MYSQL = "mysql"
    ORACLE = "oracle"
    PGSQL = "postgresql"
    SQLITE = "sqlite"
    SYBASE = "sybase"

class CUSTOM_LOGGING:
    PAYLOAD = 9
    TRAFFIC_OUT = 8
    TRAFFIC_IN = 7

class OS:
    LINUX = "Linux"
    WINDOWS = "Windows"

class PLACE:
    GET = "GET"
    POST = "POST"
    URI = "URI"
    COOKIE = "Cookie"
    USER_AGENT = "User-Agent"
    REFERER = "Referer"
    HOST = "Host"
    CUSTOM_POST = "(custom) POST"

class POST_HINT:
    SOAP = "SOAP"
    JSON = "JSON"
    XML = "XML (generic)"

class HTTPMETHOD:
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"

class NULLCONNECTION:
    HEAD = "HEAD"
    RANGE = "Range"

class REFLECTIVE_COUNTER:
    MISS = "MISS"
    HIT = "HIT"

class CHARSET_TYPE:
    BINARY = 1
    DIGITS = 2
    HEXADECIMAL = 3
    ALPHA = 4
    ALPHANUM = 5

class HEURISTIC_TEST:
    CASTED = 1
    NEGATIVE = 2
    POSITIVE = 3

class HASH:
    MYSQL = r'(?i)\A\*[0-9a-f]{40}\Z'
    MYSQL_OLD = r'(?i)\A(?![0-9]+\Z)[0-9a-f]{16}\Z'
    POSTGRES = r'(?i)\Amd5[0-9a-f]{32}\Z'
    MSSQL = r'(?i)\A0x0100[0-9a-f]{8}[0-9a-f]{40}\Z'
    MSSQL_OLD = r'(?i)\A0x0100[0-9a-f]{8}[0-9a-f]{80}\Z'
    ORACLE = r'(?i)\As:[0-9a-f]{60}\Z'
    ORACLE_OLD = r'(?i)\A[01-9a-f]{16}\Z'
    MD5_GENERIC = r'(?i)\A[0-9a-f]{32}\Z'
    SHA1_GENERIC = r'(?i)\A[0-9a-f]{40}\Z'
    CRYPT_GENERIC = r'(?i)\A(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\Z)(?![0-9]+\Z)[./0-9A-Za-z]{13}\Z'
    WORDPRESS = r'(?i)\A\$P\$[./0-9A-Za-z]{31}\Z'

# Reference: http://www.zytrax.com/tech/web/mobile_ids.html
class MOBILES:
    BLACKBERRY = "RIM Blackberry 9800 Torch;Mozilla/5.0 (BlackBerry; U; BlackBerry 9800; en-US) AppleWebKit/534.1+ (KHTML, like Gecko) Version/6.0.0.246 Mobile Safari/534.1+"
    GALAXY = "Samsung Galaxy S;Mozilla/5.0 (Linux; U; Android 2.2; en-US; SGH-T959D Build/FROYO) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1"
    HP = "HP iPAQ 6365;Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC; 240x320; HP iPAQ h6300)"
    HTC = "HTC Evo;Mozilla/5.0 (Linux; U; Android 2.2; en-us; Sprint APA9292KT Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1"
    IPHONE = "Apple iPhone 4;Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_0 like Mac OS X; en-us) AppleWebKit/532.9 (KHTML, like Gecko) Version/4.0.5 Mobile/8A293 Safari/531.22.7"
    NEXUS = "Google Nexus One;Mozilla/5.0 (Linux; U; Android 2.2; en-US; Nexus One Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1"
    NOKIA = "Nokia N97;Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 NokiaN97-1/10.0.012; Profile/MIDP-2.1 Configuration/CLDC-1.1; en-us) AppleWebKit/525 (KHTML, like Gecko) WicKed/7.1.12344"

class PROXYTYPE:
    HTTP = "HTTP"
    SOCKS4 = "SOCKS4"
    SOCKS5 = "SOCKS5"

class HTTPHEADER:
    ACCEPT = "Accept"
    ACCEPT_CHARSET = "Accept-Charset"
    ACCEPT_ENCODING = "Accept-Encoding"
    ACCEPT_LANGUAGE = "Accept-Language"
    AUTHORIZATION = "Authorization"
    CACHE_CONTROL = "Cache-Control"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    COOKIE = "Cookie"
    SET_COOKIE = "Set-Cookie"
    HOST = "Host"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    USER_AGENT = "User-Agent"

class EXPECTED:
    BOOL = "bool"
    INT = "int"

class HASHDB_KEYS:
    DBMS = "DBMS"
    CONF_TMP_PATH = "CONF_TMP_PATH"
    KB_ABS_FILE_PATHS = "KB_ABS_FILE_PATHS"
    KB_BRUTE_COLUMNS = "KB_BRUTE_COLUMNS"
    KB_BRUTE_TABLES = "KB_BRUTE_TABLES"
    KB_CHARS = "KB_CHARS"
    KB_DYNAMIC_MARKINGS = "KB_DYNAMIC_MARKINGS"
    KB_INJECTIONS = "KB_INJECTIONS"
    KB_XP_CMDSHELL_AVAILABLE = "KB_XP_CMDSHELL_AVAILABLE"
    OS = "OS"

class REDIRECTION:
    YES = "Y"
    NO = "N"

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

class WIZARD:
    BASIC = ("getBanner", "getCurrentUser", "getCurrentDb", "isDba")
    SMART = ("getBanner", "getCurrentUser", "getCurrentDb", "isDba", "getUsers", "getDbs", "getTables", "getSchema", "excludeSysDbs")
    ALL = ("getBanner", "getCurrentUser", "getCurrentDb", "isDba", "getHostname", "getUsers", "getPasswordHashes", "getPrivileges", "getRoles", "dumpAll")

class ADJUST_TIME_DELAY:
    DISABLE = -1
    NO = 0
    YES = 1
