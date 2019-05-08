#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
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

# Reference: https://docs.python.org/2/library/logging.html#logging-levels
class LOGGING_LEVELS:
    NOTSET = 0
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

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
    HSQLDB = "HSQLDB"
    H2 = "H2"
    INFORMIX = "Informix"

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
    HSQLDB = "hsqldb"
    H2 = "h2"
    INFORMIX = "informix"

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
    CUSTOM_HEADER = "(custom) HEADER"

class POST_HINT:
    SOAP = "SOAP"
    JSON = "JSON"
    JSON_LIKE = "JSON-like"
    MULTIPART = "MULTIPART"
    XML = "XML (generic)"
    ARRAY_LIKE = "Array-like"

class HTTPMETHOD:
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"
    PUT = "PUT"
    DELETE = "DELETE"
    TRACE = "TRACE"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    PATCH = "PATCH"

class NULLCONNECTION:
    HEAD = "HEAD"
    RANGE = "Range"
    SKIP_READ = "skip-read"

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
    MSSQL_NEW = r'(?i)\A0x0200[0-9a-f]{8}[0-9a-f]{128}\Z'
    ORACLE = r'(?i)\As:[0-9a-f]{60}\Z'
    ORACLE_OLD = r'(?i)\A[0-9a-f]{16}\Z'
    MD5_GENERIC = r'(?i)\A[0-9a-f]{32}\Z'
    SHA1_GENERIC = r'(?i)\A[0-9a-f]{40}\Z'
    SHA224_GENERIC = r'(?i)\A[0-9a-f]{56}\Z'
    SHA256_GENERIC = r'(?i)\A[0-9a-f]{64}\Z'
    SHA384_GENERIC = r'(?i)\A[0-9a-f]{96}\Z'
    SHA512_GENERIC = r'(?i)\A[0-9a-f]{128}\Z'
    CRYPT_GENERIC = r'\A(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\Z)(?![0-9]+\Z)[./0-9A-Za-z]{13}\Z'
    JOOMLA = r'\A[0-9a-f]{32}:\w{32}\Z'
    WORDPRESS = r'\A\$P\$[./0-9a-zA-Z]{31}\Z'
    APACHE_MD5_CRYPT = r'\A\$apr1\$.{1,8}\$[./a-zA-Z0-9]+\Z'
    UNIX_MD5_CRYPT = r'\A\$1\$.{1,8}\$[./a-zA-Z0-9]+\Z'
    APACHE_SHA1 = r'\A\{SHA\}[a-zA-Z0-9+/]+={0,2}\Z'
    VBULLETIN = r'\A[0-9a-fA-F]{32}:.{30}\Z'
    VBULLETIN_OLD = r'\A[0-9a-fA-F]{32}:.{3}\Z'
    SSHA = r'\A\{SSHA\}[a-zA-Z0-9+/]+={0,2}\Z'
    SSHA256 = r'\A\{SSHA256\}[a-zA-Z0-9+/]+={0,2}\Z'
    SSHA512 = r'\A\{SSHA512\}[a-zA-Z0-9+/]+={0,2}\Z'
    DJANGO_MD5 = r'\Amd5\$[^$]+\$[0-9a-f]{32}\Z'
    DJANGO_SHA1 = r'\Asha1\$[^$]+\$[0-9a-f]{40}\Z'
    MD5_BASE64 = r'\A[a-zA-Z0-9+/]{22}==\Z'
    SHA1_BASE64 = r'\A[a-zA-Z0-9+/]{27}=\Z'
    SHA256_BASE64 = r'\A[a-zA-Z0-9+/]{43}=\Z'
    SHA512_BASE64 = r'\A[a-zA-Z0-9+/]{86}==\Z'

# Reference: http://www.zytrax.com/tech/web/mobile_ids.html
class MOBILES:
    BLACKBERRY = ("BlackBerry Z10", "Mozilla/5.0 (BB10; Kbd) AppleWebKit/537.35+ (KHTML, like Gecko) Version/10.3.3.2205 Mobile Safari/537.35+")
    GALAXY = ("Samsung Galaxy S7", "Mozilla/5.0 (Linux; Android 7.0; SM-G930V Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Mobile Safari/537.36")
    HP = ("HP iPAQ 6365", "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC; 240x320; HP iPAQ h6300)")
    HTC = ("HTC 10", "Mozilla/5.0 (Linux; Android 8.0.0; HTC 10 Build/OPR1.170623.027) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36")
    HUAWEI = ("Huawei P8", "Mozilla/5.0 (Linux; Android 4.4.4; HUAWEI H891L Build/HuaweiH891L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mobile Safari/537.36")
    IPHONE = ("Apple iPhone 8", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1")
    LUMIA = ("Microsoft Lumia 950", "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.14977")
    NEXUS = ("Google Nexus 7", "Mozilla/5.0 (Linux; Android 4.1.1; Nexus 7 Build/JRO03D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Safari/535.19")
    NOKIA = ("Nokia N97", "Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 NokiaN97-1/10.0.012; Profile/MIDP-2.1 Configuration/CLDC-1.1; en-us) AppleWebKit/525 (KHTML, like Gecko) WicKed/7.1.12344")
    PIXEL = ("Google Pixel", "Mozilla/5.0 (Linux; Android 8.0.0; Pixel Build/OPR3.170623.013) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.111 Mobile Safari/537.36")
    XIAOMI = ("Xiaomi Mi 3", "Mozilla/5.0 (Linux; U; Android 4.4.4; en-gb; MI 3W Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/39.0.0.0 Mobile Safari/537.36 XiaoMi/MiuiBrowser/2.1.1")

class PROXY_TYPE:
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SOCKS4 = "SOCKS4"
    SOCKS5 = "SOCKS5"

class REGISTRY_OPERATION:
    READ = "read"
    ADD = "add"
    DELETE = "delete"

class DUMP_FORMAT:
    CSV = "CSV"
    HTML = "HTML"
    SQLITE = "SQLITE"

class HTTP_HEADER:
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
    EXPIRES = "Expires"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    LAST_MODIFIED = "Last-Modified"
    LOCATION = "Location"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    REFRESH = "Refresh"  # Reference: http://stackoverflow.com/a/283794
    SERVER = "Server"
    SET_COOKIE = "Set-Cookie"
    TRANSFER_ENCODING = "Transfer-Encoding"
    URI = "URI"
    USER_AGENT = "User-Agent"
    VIA = "Via"
    X_POWERED_BY = "X-Powered-By"
    X_DATA_ORIGIN = "X-Data-Origin"

class EXPECTED:
    BOOL = "bool"
    INT = "int"

class OPTION_TYPE:
    BOOLEAN = "boolean"
    INTEGER = "integer"
    FLOAT = "float"
    STRING = "string"

class HASHDB_KEYS:
    DBMS = "DBMS"
    DBMS_FORK = "DBMS_FORK"
    CHECK_WAF_RESULT = "CHECK_WAF_RESULT"
    CHECK_NULL_CONNECTION_RESULT = "CHECK_NULL_CONNECTION_RESULT"
    CONF_TMP_PATH = "CONF_TMP_PATH"
    KB_ABS_FILE_PATHS = "KB_ABS_FILE_PATHS"
    KB_BRUTE_COLUMNS = "KB_BRUTE_COLUMNS"
    KB_BRUTE_TABLES = "KB_BRUTE_TABLES"
    KB_CHARS = "KB_CHARS"
    KB_DYNAMIC_MARKINGS = "KB_DYNAMIC_MARKINGS"
    KB_INJECTIONS = "KB_INJECTIONS"
    KB_ERROR_CHUNK_LENGTH = "KB_ERROR_CHUNK_LENGTH"
    KB_XP_CMDSHELL_AVAILABLE = "KB_XP_CMDSHELL_AVAILABLE"
    OS = "OS"

class REDIRECTION:
    YES = "Y"
    NO = "N"

class PAYLOAD:
    SQLINJECTION = {
        1: "boolean-based blind",
        2: "error-based",
        3: "inline query",
        4: "stacked queries",
        5: "time-based blind",
        6: "UNION query",
    }

    PARAMETER = {
        1: "Unescaped numeric",
        2: "Single quoted string",
        3: "LIKE single quoted string",
        4: "Double quoted string",
        5: "LIKE double quoted string",
        6: "Identifier (e.g. column name)",
    }

    RISK = {
        0: "No risk",
        1: "Low risk",
        2: "Medium risk",
        3: "High risk",
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
        8: "Column name",
        9: "Pre-WHERE (non-query)",
    }

    class METHOD:
        COMPARISON = "comparison"
        GREP = "grep"
        TIME = "time"
        UNION = "union"

    class TECHNIQUE:
        BOOLEAN = 1
        ERROR = 2
        QUERY = 3
        STACKED = 4
        TIME = 5
        UNION = 6

    class WHERE:
        ORIGINAL = 1
        NEGATIVE = 2
        REPLACE = 3

class WIZARD:
    BASIC = ("getBanner", "getCurrentUser", "getCurrentDb", "isDba")
    INTERMEDIATE = ("getBanner", "getCurrentUser", "getCurrentDb", "isDba", "getUsers", "getDbs", "getTables", "getSchema", "excludeSysDbs")
    ALL = ("getBanner", "getCurrentUser", "getCurrentDb", "isDba", "getHostname", "getUsers", "getPasswordHashes", "getPrivileges", "getRoles", "dumpAll")

class ADJUST_TIME_DELAY:
    DISABLE = -1
    NO = 0
    YES = 1

class WEB_PLATFORM:
    PHP = "php"
    ASP = "asp"
    ASPX = "aspx"
    JSP = "jsp"

class CONTENT_TYPE:
    TARGET = 0
    TECHNIQUES = 1
    DBMS_FINGERPRINT = 2
    BANNER = 3
    CURRENT_USER = 4
    CURRENT_DB = 5
    HOSTNAME = 6
    IS_DBA = 7
    USERS = 8
    PASSWORDS = 9
    PRIVILEGES = 10
    ROLES = 11
    DBS = 12
    TABLES = 13
    COLUMNS = 14
    SCHEMA = 15
    COUNT = 16
    DUMP_TABLE = 17
    SEARCH = 18
    SQL_QUERY = 19
    COMMON_TABLES = 20
    COMMON_COLUMNS = 21
    FILE_READ = 22
    FILE_WRITE = 23
    OS_CMD = 24
    REG_READ = 25

class CONTENT_STATUS:
    IN_PROGRESS = 0
    COMPLETE = 1

class AUTH_TYPE:
    BASIC = "basic"
    DIGEST = "digest"
    NTLM = "ntlm"
    PKI = "pki"

class AUTOCOMPLETE_TYPE:
    SQL = 0
    OS = 1
    SQLMAP = 2
    API = 3

class NOTE:
    FALSE_POSITIVE_OR_UNEXPLOITABLE = "false positive or unexploitable"

class MKSTEMP_PREFIX:
    HASHES = "sqlmaphashes-"
    CRAWLER = "sqlmapcrawler-"
    IPC = "sqlmapipc-"
    CONFIG = "sqlmapconfig-"
    TESTING = "sqlmaptesting-"
    RESULTS = "sqlmapresults-"
    COOKIE_JAR = "sqlmapcookiejar-"
    BIG_ARRAY = "sqlmapbigarray-"
    SPECIFIC_RESPONSE = "sqlmapresponse-"
    PREPROCESS = "sqlmappreprocess-"

class TIMEOUT_STATE:
    NORMAL = 0
    EXCEPTION = 1
    TIMEOUT = 2

class HINT:
    PREPEND = 0
    APPEND = 1
