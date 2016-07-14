#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re
import subprocess
import string
import sys
import types

from lib.core.datatype import AttribDict
from lib.core.enums import DBMS
from lib.core.enums import DBMS_DIRECTORY_NAME
from lib.core.enums import OS
from lib.core.revision import getRevisionNumber

# sqlmap version (<major>.<minor>.<month>.<monthly commit>)
VERSION = "1.0.7.22"
REVISION = getRevisionNumber()
STABLE = VERSION.count('.') <= 2
VERSION_STRING = "sqlmap/%s#%s" % (VERSION, "stable" if STABLE else "dev")
DESCRIPTION = "automatic SQL injection and database takeover tool"
SITE = "http://sqlmap.org"
ISSUES_PAGE = "https://github.com/sqlmapproject/sqlmap/issues/new"
GIT_REPOSITORY = "git://github.com/sqlmapproject/sqlmap.git"
GIT_PAGE = "https://github.com/sqlmapproject/sqlmap"

# colorful banner
BANNER = """\033[01;33m         _
 ___ ___| |_____ ___ ___  \033[01;37m{\033[01;%dm%s\033[01;37m}\033[01;33m
|_ -| . | |     | .'| . |
|___|_  |_|_|_|_|__,|  _|
      |_|           |_|   \033[0m\033[4;37m%s\033[0m\n
""" % ((31 + hash(VERSION) % 6) if not STABLE else 30, VERSION_STRING.split('/')[-1], SITE)

# Minimum distance of ratio from kb.matchRatio to result in True
DIFF_TOLERANCE = 0.05
CONSTANT_RATIO = 0.9

# Ratio used in heuristic check for WAF/IDS/IPS protected targets
IDS_WAF_CHECK_RATIO = 0.5

# Timeout used in heuristic check for WAF/IDS/IPS protected targets
IDS_WAF_CHECK_TIMEOUT = 10

# Lower and upper values for match ratio in case of stable page
LOWER_RATIO_BOUND = 0.02
UPPER_RATIO_BOUND = 0.98

# Markers for special cases when parameter values contain html encoded characters
PARAMETER_AMP_MARKER = "__AMP__"
PARAMETER_SEMICOLON_MARKER = "__SEMICOLON__"
BOUNDARY_BACKSLASH_MARKER = "__BACKSLASH__"
PARTIAL_VALUE_MARKER = "__PARTIAL_VALUE__"
PARTIAL_HEX_VALUE_MARKER = "__PARTIAL_HEX_VALUE__"
URI_QUESTION_MARKER = "__QUESTION_MARK__"
ASTERISK_MARKER = "__ASTERISK_MARK__"
REPLACEMENT_MARKER = "__REPLACEMENT_MARK__"
BOUNDED_INJECTION_MARKER = "__BOUNDED_INJECTION_MARK__"

RANDOM_INTEGER_MARKER = "[RANDINT]"
RANDOM_STRING_MARKER = "[RANDSTR]"

PAYLOAD_DELIMITER = "__PAYLOAD_DELIMITER__"
CHAR_INFERENCE_MARK = "%c"
PRINTABLE_CHAR_REGEX = r"[^\x00-\x1f\x7f-\xff]"

# Regular expression used for extraction of table names (useful for (e.g.) MsAccess)
SELECT_FROM_TABLE_REGEX = r"\bSELECT .+? FROM (?P<result>[\w.]+)\b"

# Regular expression used for recognition of textual content-type
TEXT_CONTENT_TYPE_REGEX = r"(?i)(text|form|message|xml|javascript|ecmascript|json)"

# Regular expression used for recognition of generic permission messages
PERMISSION_DENIED_REGEX = r"(command|permission|access)\s*(was|is)?\s*denied"

# Regular expression used for recognition of generic maximum connection messages
MAX_CONNECTIONS_REGEX = r"max.+connections"

# Timeout before the pre-connection candidate is being disposed (because of high probability that the web server will reset it)
PRECONNECT_CANDIDATE_TIMEOUT = 10

# Regular expression used for extracting results from Google search
GOOGLE_REGEX = r"webcache\.googleusercontent\.com/search\?q=cache:[^:]+:([^+]+)\+&amp;cd=|url\?\w+=((?![^>]+webcache\.googleusercontent\.com)http[^>]+)&(sa=U|rct=j)"

# Regular expression used for extracting results from DuckDuckGo search
DUCKDUCKGO_REGEX = r'"u":"([^"]+)'

# Regular expression used for extracting results from Disconnect Search
DISCONNECT_SEARCH_REGEX = r'<p class="url wrapword">([^<]+)</p>'

# Dummy user agent for search (if default one returns different results)
DUMMY_SEARCH_USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:40.0) Gecko/20100101 Firefox/40.0"

# Regular expression used for extracting content from "textual" tags
TEXT_TAG_REGEX = r"(?si)<(abbr|acronym|b|blockquote|br|center|cite|code|dt|em|font|h\d|i|li|p|pre|q|strong|sub|sup|td|th|title|tt|u)(?!\w).*?>(?P<result>[^<]+)"

# Regular expression used for recognition of IP addresses
IP_ADDRESS_REGEX = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"

# Regular expression used for recognition of generic "your ip has been blocked" messages
BLOCKED_IP_REGEX = r"(?i)(\A|\b)ip\b.*\b(banned|blocked|block list|firewall)"

# Dumping characters used in GROUP_CONCAT MySQL technique
CONCAT_ROW_DELIMITER = ','
CONCAT_VALUE_DELIMITER = '|'

# Coefficient used for a time-based query delay checking (must be >= 7)
TIME_STDEV_COEFF = 7

# Minimum response time that can be even considered as delayed (not a complete requirement)
MIN_VALID_DELAYED_RESPONSE = 0.5

# Standard deviation after which a warning message should be displayed about connection lags
WARN_TIME_STDEV = 0.5

# Minimum length of usable union injected response (quick defense against substr fields)
UNION_MIN_RESPONSE_CHARS = 10

# Coefficient used for a union-based number of columns checking (must be >= 7)
UNION_STDEV_COEFF = 7

# Length of queue for candidates for time delay adjustment
TIME_DELAY_CANDIDATES = 3

# Default value for HTTP Accept header
HTTP_ACCEPT_HEADER_VALUE = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

# Default value for HTTP Accept-Encoding header
HTTP_ACCEPT_ENCODING_HEADER_VALUE = "gzip,deflate"

# Default timeout for running commands over backdoor
BACKDOOR_RUN_CMD_TIMEOUT = 5

# Number of seconds to wait for thread finalization at program end
THREAD_FINALIZATION_TIMEOUT = 1

# Maximum number of techniques used in inject.py/getValue() per one value
MAX_TECHNIQUES_PER_VALUE = 2

# In case of missing piece of partial union dump, buffered array must be flushed after certain size
MAX_BUFFERED_PARTIAL_UNION_LENGTH = 1024

# Suffix used for naming meta databases in DBMS(es) without explicit database name
METADB_SUFFIX = "_masterdb"

# Number of times to retry the pushValue during the exceptions (e.g. KeyboardInterrupt)
PUSH_VALUE_EXCEPTION_RETRY_COUNT = 3

# Minimum time response set needed for time-comparison based on standard deviation
MIN_TIME_RESPONSES = 30

# Minimum comparison ratio set needed for searching valid union column number based on standard deviation
MIN_UNION_RESPONSES = 5

# After these number of blanks at the end inference should stop (just in case)
INFERENCE_BLANK_BREAK = 10

# Use this replacement character for cases when inference is not able to retrieve the proper character value
INFERENCE_UNKNOWN_CHAR = '?'

# Character used for operation "greater" in inference
INFERENCE_GREATER_CHAR = ">"

# Character used for operation "equals" in inference
INFERENCE_EQUALS_CHAR = "="

# Character used for operation "not-equals" in inference
INFERENCE_NOT_EQUALS_CHAR = "!="

# String used for representation of unknown DBMS
UNKNOWN_DBMS = "Unknown"

# String used for representation of unknown DBMS version
UNKNOWN_DBMS_VERSION = "Unknown"

# Dynamicity mark length used in dynamicity removal engine
DYNAMICITY_MARK_LENGTH = 32

# Dummy user prefix used in dictionary attack
DUMMY_USER_PREFIX = "__dummy__"

# Reference: http://en.wikipedia.org/wiki/ISO/IEC_8859-1
DEFAULT_PAGE_ENCODING = "iso-8859-1"

# URL used in dummy runs
DUMMY_URL = "http://foo/bar?id=1"

# System variables
IS_WIN = subprocess.mswindows

# The name of the operating system dependent module imported. The following names have currently been registered: 'posix', 'nt', 'mac', 'os2', 'ce', 'java', 'riscos'
PLATFORM = os.name
PYVERSION = sys.version.split()[0]

# DBMS system databases
MSSQL_SYSTEM_DBS = ("Northwind", "master", "model", "msdb", "pubs", "tempdb")
MYSQL_SYSTEM_DBS = ("information_schema", "mysql")                   # Before MySQL 5.0 only "mysql"
PGSQL_SYSTEM_DBS = ("information_schema", "pg_catalog", "pg_toast")
ORACLE_SYSTEM_DBS = ("CTXSYS", "DBSNMP", "DMSYS", "EXFSYS", "MDSYS", "OLAPSYS", "ORDSYS", "OUTLN", "SYS", "SYSAUX", "SYSMAN", "SYSTEM", "TSMSYS", "WMSYS", "XDB")                      # These are TABLESPACE_NAME
SQLITE_SYSTEM_DBS = ("sqlite_master", "sqlite_temp_master")
ACCESS_SYSTEM_DBS = ("MSysAccessObjects", "MSysACEs", "MSysObjects", "MSysQueries", "MSysRelationships", "MSysAccessStorage",\
                        "MSysAccessXML", "MSysModules", "MSysModules2")
FIREBIRD_SYSTEM_DBS = ("RDB$BACKUP_HISTORY", "RDB$CHARACTER_SETS", "RDB$CHECK_CONSTRAINTS", "RDB$COLLATIONS", "RDB$DATABASE",\
                        "RDB$DEPENDENCIES", "RDB$EXCEPTIONS", "RDB$FIELDS", "RDB$FIELD_DIMENSIONS", " RDB$FILES", "RDB$FILTERS",\
                        "RDB$FORMATS", "RDB$FUNCTIONS", "RDB$FUNCTION_ARGUMENTS", "RDB$GENERATORS", "RDB$INDEX_SEGMENTS", "RDB$INDICES",\
                        "RDB$LOG_FILES", "RDB$PAGES", "RDB$PROCEDURES", "RDB$PROCEDURE_PARAMETERS", "RDB$REF_CONSTRAINTS", "RDB$RELATIONS",\
                        "RDB$RELATION_CONSTRAINTS", "RDB$RELATION_FIELDS", "RDB$ROLES", "RDB$SECURITY_CLASSES", "RDB$TRANSACTIONS", "RDB$TRIGGERS",\
                        "RDB$TRIGGER_MESSAGES", "RDB$TYPES", "RDB$USER_PRIVILEGES", "RDB$VIEW_RELATIONS")
MAXDB_SYSTEM_DBS = ("SYSINFO", "DOMAIN")
SYBASE_SYSTEM_DBS = ("master", "model", "sybsystemdb", "sybsystemprocs")
DB2_SYSTEM_DBS = ("NULLID", "SQLJ", "SYSCAT", "SYSFUN", "SYSIBM", "SYSIBMADM", "SYSIBMINTERNAL", "SYSIBMTS",\
                   "SYSPROC", "SYSPUBLIC", "SYSSTAT", "SYSTOOLS")
HSQLDB_SYSTEM_DBS = ("INFORMATION_SCHEMA", "SYSTEM_LOB")

MSSQL_ALIASES = ("microsoft sql server", "mssqlserver", "mssql", "ms")
MYSQL_ALIASES = ("mysql", "my")
PGSQL_ALIASES = ("postgresql", "postgres", "pgsql", "psql", "pg")
ORACLE_ALIASES = ("oracle", "orcl", "ora", "or")
SQLITE_ALIASES = ("sqlite", "sqlite3")
ACCESS_ALIASES = ("msaccess", "access", "jet", "microsoft access")
FIREBIRD_ALIASES = ("firebird", "mozilla firebird", "interbase", "ibase", "fb")
MAXDB_ALIASES = ("maxdb", "sap maxdb", "sap db")
SYBASE_ALIASES = ("sybase", "sybase sql server")
DB2_ALIASES = ("db2", "ibm db2", "ibmdb2")
HSQLDB_ALIASES = ("hsql", "hsqldb", "hs", "hypersql")

DBMS_DIRECTORY_DICT = dict((getattr(DBMS, _), getattr(DBMS_DIRECTORY_NAME, _)) for _ in dir(DBMS) if not _.startswith("_"))

SUPPORTED_DBMS = MSSQL_ALIASES + MYSQL_ALIASES + PGSQL_ALIASES + ORACLE_ALIASES + SQLITE_ALIASES + ACCESS_ALIASES + FIREBIRD_ALIASES + MAXDB_ALIASES + SYBASE_ALIASES + DB2_ALIASES + HSQLDB_ALIASES
SUPPORTED_OS = ("linux", "windows")

DBMS_ALIASES = ((DBMS.MSSQL, MSSQL_ALIASES), (DBMS.MYSQL, MYSQL_ALIASES), (DBMS.PGSQL, PGSQL_ALIASES), (DBMS.ORACLE, ORACLE_ALIASES), (DBMS.SQLITE, SQLITE_ALIASES), (DBMS.ACCESS, ACCESS_ALIASES), (DBMS.FIREBIRD, FIREBIRD_ALIASES), (DBMS.MAXDB, MAXDB_ALIASES), (DBMS.SYBASE, SYBASE_ALIASES), (DBMS.DB2, DB2_ALIASES), (DBMS.HSQLDB, HSQLDB_ALIASES))

USER_AGENT_ALIASES = ("ua", "useragent", "user-agent")
REFERER_ALIASES = ("ref", "referer", "referrer")
HOST_ALIASES = ("host",)

HSQLDB_DEFAULT_SCHEMA = "PUBLIC"

# Names that can't be used to name files on Windows OS
WINDOWS_RESERVED_NAMES = ("CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9")

# Items displayed in basic help (-h) output
BASIC_HELP_ITEMS = (
                        "url",
                        "googleDork",
                        "data",
                        "cookie",
                        "randomAgent",
                        "proxy",
                        "testParameter",
                        "dbms",
                        "level",
                        "risk",
                        "tech",
                        "getAll",
                        "getBanner",
                        "getCurrentUser",
                        "getCurrentDb",
                        "getPasswordHashes",
                        "getTables",
                        "getColumns",
                        "getSchema",
                        "dumpTable",
                        "dumpAll",
                        "db",
                        "tbl",
                        "col",
                        "osShell",
                        "osPwn",
                        "batch",
                        "checkTor",
                        "flushSession",
                        "tor",
                        "sqlmapShell",
                        "wizard",
                   )

# String representation for NULL value
NULL = "NULL"

# String representation for blank ('') value
BLANK = "<blank>"

# String representation for current database
CURRENT_DB = "CD"

# Regular expressions used for finding file paths in error messages
FILE_PATH_REGEXES = (r" in (file )?<b>(?P<result>.*?)</b> on line", r"(?:[>(\[\s])(?P<result>[A-Za-z]:[\\/][\w.\\/-]*)", r"(?:[>(\[\s])(?P<result>/\w[/\w.-]+)", r"href=['\"]file://(?P<result>/[^'\"]+)")

# Regular expressions used for parsing error messages (--parse-errors)
ERROR_PARSING_REGEXES = (
                          r"<b>[^<]*(fatal|error|warning|exception)[^<]*</b>:?\s*(?P<result>.+?)<br\s*/?\s*>",
                          r"(?m)^(fatal|error|warning|exception):?\s*(?P<result>[^\n]+?)$",
                          r"<li>Error Type:<br>(?P<result>.+?)</li>",
                          r"error '[0-9a-f]{8}'((<[^>]+>)|\s)+(?P<result>[^<>]+)",
                          r"(?m)^\s*\[[^\n]+(ODBC|JDBC)[^\n]+\](?P<result>[^\]]+in query expression[^\n]+)$"
                        )

# Regular expression used for parsing charset info from meta html headers
META_CHARSET_REGEX = r'(?si)<head>.*<meta[^>]+charset="?(?P<result>[^"> ]+).*</head>'

# Regular expression used for parsing refresh info from meta html headers
META_REFRESH_REGEX = r'(?si)<head>(?!.*?<noscript.*?</head).*?<meta http-equiv="?refresh"?[^>]+content="?[^">]+url=["\']?(?P<result>[^\'">]+).*</head>'

# Regular expression used for parsing empty fields in tested form data
EMPTY_FORM_FIELDS_REGEX = r'(&|\A)(?P<result>[^=]+=(&|\Z))'

# Reference: http://www.cs.ru.nl/bachelorscripties/2010/Martin_Devillers___0437999___Analyzing_password_strength.pdf
COMMON_PASSWORD_SUFFIXES = ("1", "123", "2", "12", "3", "13", "7", "11", "5", "22", "23", "01", "4", "07", "21", "14", "10", "06", "08", "8", "15", "69", "16", "6", "18")

# Reference: http://www.the-interweb.com/serendipity/index.php?/archives/94-A-brief-analysis-of-40,000-leaked-MySpace-passwords.html
COMMON_PASSWORD_SUFFIXES += ("!", ".", "*", "!!", "?", ";", "..", "!!!", ", ", "@")

# Splitter used between requests in WebScarab log files
WEBSCARAB_SPLITTER = "### Conversation"

# Splitter used between requests in BURP log files
BURP_REQUEST_REGEX = r"={10,}\s+[^=]+={10,}\s(.+?)\s={10,}"

# Regex used for parsing XML Burp saved history items
BURP_XML_HISTORY_REGEX = r'<port>(\d+)</port>.+?<request base64="true"><!\[CDATA\[([^]]+)'

# Encoding used for Unicode data
UNICODE_ENCODING = "utf8"

# Reference: http://www.w3.org/Protocols/HTTP/Object_Headers.html#uri
URI_HTTP_HEADER = "URI"

# Uri format which could be injectable (e.g. www.site.com/id82)
URI_INJECTABLE_REGEX = r"//[^/]*/([^\.*?]+)\Z"

# Regex used for masking sensitive data
SENSITIVE_DATA_REGEX = "(\s|=)(?P<result>[^\s=]*%s[^\s]*)\s"

# Maximum number of threads (avoiding connection issues and/or DoS)
MAX_NUMBER_OF_THREADS = 10

# Minimum range between minimum and maximum of statistical set
MIN_STATISTICAL_RANGE = 0.01

# Minimum value for comparison ratio
MIN_RATIO = 0.0

# Maximum value for comparison ratio
MAX_RATIO = 1.0

# Character used for marking injectable position inside provided data
CUSTOM_INJECTION_MARK_CHAR = '*'

# Other way to declare injection position
INJECT_HERE_MARK = '%INJECT HERE%'

# Minimum chunk length used for retrieving data over error based payloads
MIN_ERROR_CHUNK_LENGTH = 8

# Maximum chunk length used for retrieving data over error based payloads
MAX_ERROR_CHUNK_LENGTH = 1024

# Do not escape the injected statement if it contains any of the following SQL keywords
EXCLUDE_UNESCAPE = ("WAITFOR DELAY ", " INTO DUMPFILE ", " INTO OUTFILE ", "CREATE ", "BULK ", "EXEC ", "RECONFIGURE ", "DECLARE ", "'%s'" % CHAR_INFERENCE_MARK)

# Mark used for replacement of reflected values
REFLECTED_VALUE_MARKER = "__REFLECTED_VALUE__"

# Regular expression used for replacing border non-alphanum characters
REFLECTED_BORDER_REGEX = r"[^A-Za-z]+"

# Regular expression used for replacing non-alphanum characters
REFLECTED_REPLACEMENT_REGEX = r".+"

# Maximum number of alpha-numerical parts in reflected regex (for speed purposes)
REFLECTED_MAX_REGEX_PARTS = 10

# Chars which can be used as a failsafe values in case of too long URL encoding value
URLENCODE_FAILSAFE_CHARS = "()|,"

# Maximum length of URL encoded value after which failsafe procedure takes away
URLENCODE_CHAR_LIMIT = 2000

# Default schema for Microsoft SQL Server DBMS
DEFAULT_MSSQL_SCHEMA = "dbo"

# Display hash attack info every mod number of items
HASH_MOD_ITEM_DISPLAY = 11

# Maximum integer value
MAX_INT = sys.maxint

# Options that need to be restored in multiple targets run mode
RESTORE_MERGED_OPTIONS = ("col", "db", "dnsName", "privEsc", "tbl", "regexp", "string", "textOnly", "threads", "timeSec", "tmpPath", "uChar", "user")

# Parameters to be ignored in detection phase (upper case)
IGNORE_PARAMETERS = ("__VIEWSTATE", "__VIEWSTATEENCRYPTED", "__EVENTARGUMENT", "__EVENTTARGET", "__EVENTVALIDATION", "ASPSESSIONID", "ASP.NET_SESSIONID", "JSESSIONID", "CFID", "CFTOKEN")

# Regular expression used for recognition of ASP.NET control parameters
ASP_NET_CONTROL_REGEX = r"(?i)\Actl\d+\$"

# Prefix for Google analytics cookie names
GOOGLE_ANALYTICS_COOKIE_PREFIX = "__UTM"

# Prefix for configuration overriding environment variables
SQLMAP_ENVIRONMENT_PREFIX = "SQLMAP_"

# Turn off resume console info to avoid potential slowdowns
TURN_OFF_RESUME_INFO_LIMIT = 20

# Strftime format for results file used in multiple target mode
RESULTS_FILE_FORMAT = "results-%m%d%Y_%I%M%p.csv"

# Official web page with the list of Python supported codecs
CODECS_LIST_PAGE = "http://docs.python.org/library/codecs.html#standard-encodings"

# Simple regular expression used to distinguish scalar from multiple-row commands (not sole condition)
SQL_SCALAR_REGEX = r"\A(SELECT(?!\s+DISTINCT\(?))?\s*\w*\("

# Option/switch values to ignore during configuration save
IGNORE_SAVE_OPTIONS = ("saveConfig",)

# IP address of the localhost
LOCALHOST = "127.0.0.1"

# Default port used by Tor
DEFAULT_TOR_SOCKS_PORT = 9050

# Default ports used in Tor proxy bundles
DEFAULT_TOR_HTTP_PORTS = (8123, 8118)

# Percentage below which comparison engine could have problems
LOW_TEXT_PERCENT = 20

# These MySQL keywords can't go (alone) into versioned comment form (/*!...*/)
# Reference: http://dev.mysql.com/doc/refman/5.1/en/function-resolution.html
IGNORE_SPACE_AFFECTED_KEYWORDS = ("CAST", "COUNT", "EXTRACT", "GROUP_CONCAT", "MAX", "MID", "MIN", "SESSION_USER", "SUBSTR", "SUBSTRING", "SUM", "SYSTEM_USER", "TRIM")

LEGAL_DISCLAIMER = "Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program"

# After this number of misses reflective removal mechanism is turned off (for speed up reasons)
REFLECTIVE_MISS_THRESHOLD = 20

# Regular expression used for extracting HTML title
HTML_TITLE_REGEX = "<title>(?P<result>[^<]+)</title>"

# Table used for Base64 conversion in WordPress hash cracking routine
ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

PICKLE_REDUCE_WHITELIST = (types.BooleanType, types.DictType, types.FloatType, types.IntType, types.ListType, types.LongType, types.NoneType, types.StringType, types.TupleType, types.UnicodeType, types.XRangeType, type(AttribDict()), type(set()))

# Chars used to quickly distinguish if the user provided tainted parameter values
DUMMY_SQL_INJECTION_CHARS = ";()'"

# Simple check against dummy users
DUMMY_USER_INJECTION = r"(?i)[^\w](AND|OR)\s+[^\s]+[=><]|\bUNION\b.+\bSELECT\b|\bSELECT\b.+\bFROM\b|\b(CONCAT|information_schema|SLEEP|DELAY)\b"

# Extensions skipped by crawler
CRAWL_EXCLUDE_EXTENSIONS = ('3ds', '3g2', '3gp', '7z', 'DS_Store', 'a', 'aac', 'adp', 'ai', 'aif', 'aiff', 'apk', 'ar', 'asf', 'au', 'avi', 'bak', 'bin', 'bk', 'bmp', 'btif', 'bz2', 'cab', 'caf', 'cgm', 'cmx', 'cpio', 'cr2', 'dat', 'deb', 'djvu', 'dll', 'dmg', 'dmp', 'dng', 'doc', 'docx', 'dot', 'dotx', 'dra', 'dsk', 'dts', 'dtshd', 'dvb', 'dwg', 'dxf', 'ear', 'ecelp4800', 'ecelp7470', 'ecelp9600', 'egg', 'eol', 'eot', 'epub', 'exe', 'f4v', 'fbs', 'fh', 'fla', 'flac', 'fli', 'flv', 'fpx', 'fst', 'fvt', 'g3', 'gif', 'gz', 'h261', 'h263', 'h264', 'ico', 'ief', 'image', 'img', 'ipa', 'iso', 'jar', 'jpeg', 'jpg', 'jpgv', 'jpm', 'jxr', 'ktx', 'lvp', 'lz', 'lzma', 'lzo', 'm3u', 'm4a', 'm4v', 'mar', 'mdi', 'mid', 'mj2', 'mka', 'mkv', 'mmr', 'mng', 'mov', 'movie', 'mp3', 'mp4', 'mp4a', 'mpeg', 'mpg', 'mpga', 'mxu', 'nef', 'npx', 'o', 'oga', 'ogg', 'ogv', 'otf', 'pbm', 'pcx', 'pdf', 'pea', 'pgm', 'pic', 'png', 'pnm', 'ppm', 'pps', 'ppt', 'pptx', 'ps', 'psd', 'pya', 'pyc', 'pyo', 'pyv', 'qt', 'rar', 'ras', 'raw', 'rgb', 'rip', 'rlc', 'rz', 's3m', 's7z', 'scm', 'scpt', 'sgi', 'shar', 'sil', 'smv', 'so', 'sub', 'swf', 'tar', 'tbz2', 'tga', 'tgz', 'tif', 'tiff', 'tlz', 'ts', 'ttf', 'uvh', 'uvi', 'uvm', 'uvp', 'uvs', 'uvu', 'viv', 'vob', 'war', 'wav', 'wax', 'wbmp', 'wdp', 'weba', 'webm', 'webp', 'whl', 'wm', 'wma', 'wmv', 'wmx', 'woff', 'woff2', 'wvx', 'xbm', 'xif', 'xls', 'xlsx', 'xlt', 'xm', 'xpi', 'xpm', 'xwd', 'xz', 'z', 'zip', 'zipx')

# Patterns often seen in HTTP headers containing custom injection marking character
PROBLEMATIC_CUSTOM_INJECTION_PATTERNS = r"(;q=[^;']+)|(\*/\*)"

# Template used for common table existence check
BRUTE_TABLE_EXISTS_TEMPLATE = "EXISTS(SELECT %d FROM %s)"

# Template used for common column existence check
BRUTE_COLUMN_EXISTS_TEMPLATE = "EXISTS(SELECT %s FROM %s)"

# Payload used for checking of existence of IDS/IPS/WAF (dummier the better)
IDS_WAF_CHECK_PAYLOAD = "AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"

# Data inside shellcodeexec to be filled with random string
SHELLCODEEXEC_RANDOM_STRING_MARKER = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Vectors used for provoking specific WAF/IDS/IPS behavior(s)
WAF_ATTACK_VECTORS = (
                        "",  # NIL
                        "search=<script>alert(1)</script>",
                        "file=../../../../etc/passwd",
                        "q=<invalid>foobar",
                        "id=1 %s" % IDS_WAF_CHECK_PAYLOAD
                     )

# Used for status representation in dictionary attack phase
ROTATING_CHARS = ('\\', '|', '|', '/', '-')

# Approximate chunk length (in bytes) used by BigArray objects (only last chunk and cached one are held in memory)
BIGARRAY_CHUNK_SIZE = 1024 * 1024

# Maximum number of socket pre-connects
SOCKET_PRE_CONNECT_QUEUE_SIZE = 3

# Only console display last n table rows
TRIM_STDOUT_DUMP_SIZE = 256

# Reference: http://stackoverflow.com/a/3168436
# Reference: https://support.microsoft.com/en-us/kb/899149
DUMP_FILE_BUFFER_SIZE = 1024

# Parse response headers only first couple of times
PARSE_HEADERS_LIMIT = 3

# Step used in ORDER BY technique used for finding the right number of columns in UNION query injections
ORDER_BY_STEP = 10

# Maximum number of times for revalidation of a character in time-based injections
MAX_TIME_REVALIDATION_STEPS = 5

# Characters that can be used to split parameter values in provided command line (e.g. in --tamper)
PARAMETER_SPLITTING_REGEX = r'[,|;]'

# Regular expression describing possible union char value (e.g. used in --union-char)
UNION_CHAR_REGEX = r'\A\w+\Z'

# Attribute used for storing original parameter value in special cases (e.g. POST)
UNENCODED_ORIGINAL_VALUE = 'original'

# Common column names containing usernames (used for hash cracking in some cases)
COMMON_USER_COLUMNS = ('user', 'username', 'user_name', 'benutzername', 'benutzer', 'utilisateur', 'usager', 'consommateur', 'utente', 'utilizzatore', 'usufrutuario', 'korisnik', 'usuario', 'consumidor')

# Default delimiter in GET/POST values
DEFAULT_GET_POST_DELIMITER = '&'

# Default delimiter in cookie values
DEFAULT_COOKIE_DELIMITER = ';'

# Unix timestamp used for forcing cookie expiration when provided with --load-cookies
FORCE_COOKIE_EXPIRATION_TIME = "9999999999"

# Github OAuth token used for creating an automatic Issue for unhandled exceptions
GITHUB_REPORT_OAUTH_TOKEN = "YzNkYTgyMTdjYzdjNjZjMjFjMWE5ODI5OGQyNzk2ODM1M2M0MzUyOA=="

# Skip unforced HashDB flush requests below the threshold number of cached items
HASHDB_FLUSH_THRESHOLD = 32

# Number of retries for unsuccessful HashDB flush attempts
HASHDB_FLUSH_RETRIES = 3

# Number of retries for unsuccessful HashDB end transaction attempts
HASHDB_END_TRANSACTION_RETRIES = 3

# Unique milestone value used for forced deprecation of old HashDB values (e.g. when changing hash/pickle mechanism)
HASHDB_MILESTONE_VALUE = "pGBhWXgbtJ"  # import random, string; print "".join(random.sample(string.ascii_letters, 10))

# Warn user of possible delay due to large page dump in full UNION query injections
LARGE_OUTPUT_THRESHOLD = 1024 ** 2

# On huge tables there is a considerable slowdown if every row retrieval requires ORDER BY (most noticable in table dumping using ERROR injections)
SLOW_ORDER_COUNT_THRESHOLD = 10000

# Give up on hash recognition if nothing was found in first given number of rows
HASH_RECOGNITION_QUIT_THRESHOLD = 10000

# Maximum number of redirections to any single URL - this is needed because of the state that cookies introduce
MAX_SINGLE_URL_REDIRECTIONS = 4

# Maximum total number of redirections (regardless of URL) - before assuming we're in a loop
MAX_TOTAL_REDIRECTIONS = 10

# Reference: http://www.tcpipguide.com/free/t_DNSLabelsNamesandSyntaxRules.htm
MAX_DNS_LABEL = 63

# Alphabet used for prefix and suffix strings of name resolution requests in DNS technique (excluding hexadecimal chars for not mixing with inner content)
DNS_BOUNDARIES_ALPHABET = re.sub("[a-fA-F]", "", string.ascii_letters)

# Alphabet used for heuristic checks
HEURISTIC_CHECK_ALPHABET = ('"', '\'', ')', '(', ',', '.')

# String used for dummy non-SQLi (e.g. XSS) heuristic checks of a tested parameter value
DUMMY_NON_SQLI_CHECK_APPENDIX = "<'\">"

# Regular expression used for recognition of file inclusion errors
FI_ERROR_REGEX = "(?i)[^\n]*(no such file|failed (to )?open)[^\n]*"

# Length of prefix and suffix used in non-SQLI heuristic checks
NON_SQLI_CHECK_PREFIX_SUFFIX_LENGTH = 6

# Connection chunk size (processing large responses in chunks to avoid MemoryError crashes - e.g. large table dump in full UNION injections)
MAX_CONNECTION_CHUNK_SIZE = 10 * 1024 * 1024

# Maximum response total page size (trimmed if larger)
MAX_CONNECTION_TOTAL_SIZE = 100 * 1024 * 1024

# For preventing MemoryError exceptions (caused when using large sequences in difflib.SequenceMatcher)
MAX_DIFFLIB_SEQUENCE_LENGTH = 10 * 1024 * 1024

# Maximum (multi-threaded) length of entry in bisection algorithm
MAX_BISECTION_LENGTH = 50 * 1024 * 1024

# Mark used for trimming unnecessary content in large chunks
LARGE_CHUNK_TRIM_MARKER = "__TRIMMED_CONTENT__"

# Generic SQL comment formation
GENERIC_SQL_COMMENT = "-- [RANDSTR]"

# Threshold value for turning back on time auto-adjustment mechanism
VALID_TIME_CHARS_RUN_THRESHOLD = 100

# Check for empty columns only if table is sufficiently large
CHECK_ZERO_COLUMNS_THRESHOLD = 10

# Boldify all logger messages containing these "patterns"
BOLD_PATTERNS = ("' injectable", "provided empty", "leftover chars", "might be injectable", "' is vulnerable", "is not injectable", "test failed", "test passed", "live test final result", "test shows that", "the back-end DBMS is", "created Github", "blocked by the target server", "protection is involved")

# Generic www root directory names
GENERIC_DOC_ROOT_DIRECTORY_NAMES = ("htdocs", "httpdocs", "public", "wwwroot", "www")

# Maximum length of a help part containing switch/option name(s)
MAX_HELP_OPTION_LENGTH = 18

# Maximum number of connection retries (to prevent problems with recursion)
MAX_CONNECT_RETRIES = 100

# Strings for detecting formatting errors
FORMAT_EXCEPTION_STRINGS = ("Type mismatch", "Error converting", "Conversion failed", "String or binary data would be truncated", "Failed to convert", "unable to interpret text value", "Input string was not in a correct format", "System.FormatException", "java.lang.NumberFormatException", "ValueError: invalid literal", "DataTypeMismatchException", "CF_SQL_INTEGER", " for CFSQLTYPE ", "cfqueryparam cfsqltype", "InvalidParamTypeException", "Invalid parameter type", "is not of type numeric", "<cfif Not IsNumeric(", "invalid input syntax for integer", "invalid input syntax for type", "invalid number", "character to number conversion error", "unable to interpret text value", "String was not recognized as a valid", "Convert.ToInt", "cannot be converted to a ", "InvalidDataException")

# Regular expression used for extracting ASP.NET view state values
VIEWSTATE_REGEX = r'(?i)(?P<name>__VIEWSTATE[^"]*)[^>]+value="(?P<result>[^"]+)'

# Regular expression used for extracting ASP.NET event validation values
EVENTVALIDATION_REGEX = r'(?i)(?P<name>__EVENTVALIDATION[^"]*)[^>]+value="(?P<result>[^"]+)'

# Number of rows to generate inside the full union test for limited output (mustn't be too large to prevent payload length problems)
LIMITED_ROWS_TEST_NUMBER = 15

# Default adapter to use for bottle server
RESTAPI_DEFAULT_ADAPTER = "wsgiref"

# Default REST-JSON API server listen address
RESTAPI_DEFAULT_ADDRESS = "127.0.0.1"

# Default REST-JSON API server listen port
RESTAPI_DEFAULT_PORT = 8775

# Format used for representing invalid unicode characters
INVALID_UNICODE_CHAR_FORMAT = r"\x%02x"

# Regular expression for XML POST data
XML_RECOGNITION_REGEX = r"(?s)\A\s*<[^>]+>(.+>)?\s*\Z"

# Regular expression used for detecting JSON POST data
JSON_RECOGNITION_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]+"|\d+).*\}\s*(\]\s*)*\Z'

# Regular expression used for detecting JSON-like POST data
JSON_LIKE_RECOGNITION_REGEX = r"(?s)\A(\s*\[)*\s*\{.*'[^']+'\s*:\s*('[^']+'|\d+).*\}\s*(\]\s*)*\Z"

# Regular expression used for detecting multipart POST data
MULTIPART_RECOGNITION_REGEX = r"(?i)Content-Disposition:[^;]+;\s*name="

# Regular expression used for detecting Array-like POST data
ARRAY_LIKE_RECOGNITION_REGEX = r"(\A|%s)(\w+)\[\]=.+%s\2\[\]=" % (DEFAULT_GET_POST_DELIMITER, DEFAULT_GET_POST_DELIMITER)

# Default POST data content-type
DEFAULT_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8"

# Raw text POST data content-type
PLAIN_TEXT_CONTENT_TYPE = "text/plain; charset=utf-8"

# Length used while checking for existence of Suhosin-patch (like) protection mechanism
SUHOSIN_MAX_VALUE_LENGTH = 512

# Minimum size of an (binary) entry before it can be considered for dumping to disk
MIN_BINARY_DISK_DUMP_SIZE = 100

# Regular expression used for extracting form tags
FORM_SEARCH_REGEX = r"(?si)<form(?!.+<form).+?</form>"

# Maximum number of lines to save in history file
MAX_HISTORY_LENGTH = 1000

# Minimum field entry length needed for encoded content (hex, base64,...) check
MIN_ENCODED_LEN_CHECK = 5

# Timeout in seconds in which Metasploit remote session has to be initialized
METASPLOIT_SESSION_TIMEOUT = 300

# Reference: http://www.postgresql.org/docs/9.0/static/catalog-pg-largeobject.html
LOBLKSIZE = 2048

# Suffix used to mark variables having keyword names
EVALCODE_KEYWORD_SUFFIX = "_KEYWORD"

# Reference: http://www.cookiecentral.com/faq/#3.5
NETSCAPE_FORMAT_HEADER_COOKIES = "# Netscape HTTP Cookie File."

# Infixes used for automatic recognition of parameters carrying anti-CSRF tokens
CSRF_TOKEN_PARAMETER_INFIXES = ("csrf", "xsrf")

# Prefixes used in brute force search for web server document root
BRUTE_DOC_ROOT_PREFIXES = {
    OS.LINUX: ("/var/www", "/usr/local/apache", "/usr/local/apache2", "/usr/local/www/apache22", "/usr/local/www/apache24", "/usr/local/httpd", "/var/www/nginx-default", "/srv/www", "/var/www/%TARGET%", "/var/www/vhosts/%TARGET%", "/var/www/virtual/%TARGET%", "/var/www/clients/vhosts/%TARGET%", "/var/www/clients/virtual/%TARGET%"),
    OS.WINDOWS: ("/xampp", "/Program Files/xampp", "/wamp", "/Program Files/wampp", "/apache", "/Program Files/Apache Group/Apache", "/Program Files/Apache Group/Apache2", "/Program Files/Apache Group/Apache2.2", "/Program Files/Apache Group/Apache2.4", "/Inetpub/wwwroot", "/Inetpub/wwwroot/%TARGET%", "/Inetpub/vhosts/%TARGET%")
}

# Suffixes used in brute force search for web server document root
BRUTE_DOC_ROOT_SUFFIXES = ("", "html", "htdocs", "httpdocs", "php", "public", "src", "site", "build", "web", "www", "data", "sites/all", "www/build")

# String used for marking target name inside used brute force web server document root
BRUTE_DOC_ROOT_TARGET_MARK = "%TARGET%"

# Character used as a boundary in kb.chars (preferably less frequent letter)
KB_CHARS_BOUNDARY_CHAR = 'q'

# Letters of lower frequency used in kb.chars
KB_CHARS_LOW_FREQUENCY_ALPHABET = "zqxjkvbp"

# CSS style used in HTML dump format
HTML_DUMP_CSS_STYLE = """<style>
table{
    margin:10;
    background-color:#FFFFFF;
    font-family:verdana;
    font-size:12px;
    align:center;
}
thead{
    font-weight:bold;
    background-color:#4F81BD;
    color:#FFFFFF;
}
tr:nth-child(even) {
    background-color: #D3DFEE
}
td{
    font-size:10px;
}
th{
    font-size:10px;
}
</style>"""
