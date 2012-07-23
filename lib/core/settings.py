#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re
import subprocess
import string
import sys

from lib.core.enums import DBMS
from lib.core.enums import DBMS_DIRECTORY_NAME
from lib.core.revision import getRevisionNumber

# sqlmap version and site
VERSION = "1.0-dev"
REVISION = getRevisionNumber()
VERSION_STRING = "sqlmap/%s%s" % (VERSION, "-%s" % REVISION if REVISION else "")
DESCRIPTION = "automatic SQL injection and database takeover tool"
SITE = "http://sqlmap.org"
ISSUES_PAGE = "https://github.com/sqlmapproject/sqlmap/issues/new"
GIT_REPOSITORY = "git://github.com/sqlmapproject/sqlmap.git"
ML = "sqlmap-users@lists.sourceforge.net"

# minimum distance of ratio from kb.matchRatio to result in True
DIFF_TOLERANCE = 0.05
CONSTANT_RATIO = 0.9

# lower and upper values for match ratio in case of stable page
LOWER_RATIO_BOUND = 0.02
UPPER_RATIO_BOUND = 0.98

# markers for special cases when parameter values contain html encoded characters
PARAMETER_AMP_MARKER = "__AMP__"
PARAMETER_SEMICOLON_MARKER = "__SEMICOLON__"

PARTIAL_VALUE_MARKER = "__PARTIAL__"

URI_QUESTION_MARKER = "__QUESTION_MARK__"

PAYLOAD_DELIMITER = "\x00"
CHAR_INFERENCE_MARK = "%c"
PRINTABLE_CHAR_REGEX = r"[^\x00-\x1f\x7e-\xff]"

# regular expression used for extracting results from google search
GOOGLE_REGEX = r"url\?\w+=(http[^>]+)&amp;(sa=U|rct=j)"

# regular expression used for extracting content from "textual" tags
TEXT_TAG_REGEX = r"(?si)<(abbr|acronym|b|blockquote|br|center|cite|code|dt|em|font|h\d|i|li|p|pre|q|strong|sub|sup|td|th|title|tt|u)(?!\w).*?>(?P<result>[^<]+)"

# dumping characters used in GROUP_CONCAT MySQL technique
CONCAT_ROW_DELIMITER = ','
CONCAT_VALUE_DELIMITER = '|'

# coefficient used for a time-based query delay checking (must be >= 7)
TIME_STDEV_COEFF = 7

# standard deviation after which a warning message should be displayed about connection lags
WARN_TIME_STDEV = 0.5

# minimum length of usable union injected response (quick defense against substr fields)
UNION_MIN_RESPONSE_CHARS = 10

# coefficient used for a union-based number of columns checking (must be >= 7)
UNION_STDEV_COEFF = 7

# length of queue for candidates for time delay adjustment
TIME_DELAY_CANDIDATES = 3

# default value for HTTP Accept header
HTTP_ACCEPT_HEADER_VALUE = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

# default value for HTTP Accept-Encoding header
HTTP_ACCEPT_ENCODING_HEADER_VALUE = "gzip,deflate"

# HTTP timeout in silent mode
HTTP_SILENT_TIMEOUT = 3

# maximum number of techniques used in inject.py/getValue() per one value
MAX_TECHNIQUES_PER_VALUE = 2

# suffix used for naming meta databases in DBMS(es) without explicit database name
METADB_SUFFIX = "_masterdb"

# minimum time response set needed for time-comparison based on standard deviation
MIN_TIME_RESPONSES = 10

# minimum comparison ratio set needed for searching valid union column number based on standard deviation
MIN_UNION_RESPONSES = 5

# after these number of blanks at the end inference should stop (just in case)
INFERENCE_BLANK_BREAK = 10

# use this replacement character for cases when inference is not able to retrieve the proper character value
INFERENCE_UNKNOWN_CHAR = '?'

# character used for operation "greater" in inference
INFERENCE_GREATER_CHAR = ">"

# character used for operation "equals" in inference
INFERENCE_EQUALS_CHAR = "="

# character used for operation "not-equals" in inference
INFERENCE_NOT_EQUALS_CHAR = "!="

# string used for representation of unknown dbms version
UNKNOWN_DBMS_VERSION = "Unknown"

# dynamicity mark length used in dynamicity removal engine
DYNAMICITY_MARK_LENGTH = 32

# length of FIFO buffer for removing possible duplicates in union/inband data retrieval
UNION_UNIQUE_FIFO_LENGTH = 10

# dummy user prefix used in dictionary attack
DUMMY_USER_PREFIX = "__dummy__"

# Reference: http://en.wikipedia.org/wiki/ISO/IEC_8859-1
DEFAULT_PAGE_ENCODING = "iso-8859-1"

# System variables
IS_WIN = subprocess.mswindows
# The name of the operating system dependent module imported. The following
# names have currently been registered: 'posix', 'nt', 'mac', 'os2', 'ce',
# 'java', 'riscos'
PLATFORM = os.name
PYVERSION = sys.version.split()[0]

# Database management system specific variables
MSSQL_SYSTEM_DBS = ( "Northwind", "master", "model", "msdb", "pubs", "tempdb" )
MYSQL_SYSTEM_DBS = ( "information_schema", "mysql" )                   # Before MySQL 5.0 only "mysql"
PGSQL_SYSTEM_DBS = ( "information_schema", "pg_catalog", "pg_toast" )
ORACLE_SYSTEM_DBS = ( "SYSTEM", "SYSAUX", "SYS" )                      # These are TABLESPACE_NAME
SQLITE_SYSTEM_DBS = ( "sqlite_master", "sqlite_temp_master" )
ACCESS_SYSTEM_DBS = ( "MSysAccessObjects", "MSysACEs", "MSysObjects", "MSysQueries", "MSysRelationships", "MSysAccessStorage",\
                        "MSysAccessXML", "MSysModules", "MSysModules2" )
FIREBIRD_SYSTEM_DBS = ( "RDB$BACKUP_HISTORY", "RDB$CHARACTER_SETS", "RDB$CHECK_CONSTRAINTS", "RDB$COLLATIONS", "RDB$DATABASE",\
                        "RDB$DEPENDENCIES", "RDB$EXCEPTIONS", "RDB$FIELDS", "RDB$FIELD_DIMENSIONS", " RDB$FILES", "RDB$FILTERS",\
                        "RDB$FORMATS", "RDB$FUNCTIONS", "RDB$FUNCTION_ARGUMENTS", "RDB$GENERATORS", "RDB$INDEX_SEGMENTS", "RDB$INDICES",\
                        "RDB$LOG_FILES", "RDB$PAGES", "RDB$PROCEDURES", "RDB$PROCEDURE_PARAMETERS", "RDB$REF_CONSTRAINTS", "RDB$RELATIONS",\
                        "RDB$RELATION_CONSTRAINTS", "RDB$RELATION_FIELDS", "RDB$ROLES", "RDB$SECURITY_CLASSES", "RDB$TRANSACTIONS", "RDB$TRIGGERS",\
                        "RDB$TRIGGER_MESSAGES", "RDB$TYPES", "RDB$USER_PRIVILEGES", "RDB$VIEW_RELATIONS" )
MAXDB_SYSTEM_DBS = ( "SYSINFO", "DOMAIN" )
SYBASE_SYSTEM_DBS = ( "master", "model", "sybsystemdb", "sybsystemprocs" )
DB2_SYSTEM_DBS = ( "NULLID", "SQLJ", "SYSCAT", "SYSFUN", "SYSIBM", "SYSIBMADM", "SYSIBMINTERNAL", "SYSIBMTS",\
                   "SYSPROC", "SYSPUBLIC", "SYSSTAT", "SYSTOOLS" )

MSSQL_ALIASES = ( "microsoft sql server", "mssqlserver", "mssql", "ms" )
MYSQL_ALIASES = ( "mysql", "my" )
PGSQL_ALIASES = ( "postgresql", "postgres", "pgsql", "psql", "pg" )
ORACLE_ALIASES = ( "oracle", "orcl", "ora", "or" )
SQLITE_ALIASES = ( "sqlite", "sqlite3" )
ACCESS_ALIASES = ( "msaccess", "access", "jet", "microsoft access" )
FIREBIRD_ALIASES = ( "firebird", "mozilla firebird", "interbase", "ibase", "fb" )
MAXDB_ALIASES = ( "maxdb", "sap maxdb", "sap db" )
SYBASE_ALIASES = ( "sybase", "sybase sql server" )
DB2_ALIASES = ( "db2", "ibm db2", "ibmdb2" )

DBMS_DIRECTORY_DICT = dict((getattr(DBMS, _), getattr(DBMS_DIRECTORY_NAME, _)) for _ in dir(DBMS) if not _.startswith("_"))

SUPPORTED_DBMS = MSSQL_ALIASES + MYSQL_ALIASES + PGSQL_ALIASES + ORACLE_ALIASES + SQLITE_ALIASES + ACCESS_ALIASES + FIREBIRD_ALIASES + MAXDB_ALIASES + SYBASE_ALIASES + DB2_ALIASES
SUPPORTED_OS = ( "linux", "windows" )

DBMS_DICT = {
                DBMS.MSSQL: (MSSQL_ALIASES, "python-pymssql", "http://pymssql.sourceforge.net/"),
                DBMS.MYSQL: (MYSQL_ALIASES, "python pymysql", "http://code.google.com/p/pymysql/"),
                DBMS.PGSQL: (PGSQL_ALIASES, "python-psycopg2", "http://initd.org/psycopg/"),
                DBMS.ORACLE: (ORACLE_ALIASES, "python cx_Oracle", "http://cx-oracle.sourceforge.net/"),
                DBMS.SQLITE: (SQLITE_ALIASES, "python-pysqlite2", "http://pysqlite.googlecode.com/"),
                DBMS.ACCESS: (ACCESS_ALIASES, "python-pyodbc", "http://pyodbc.googlecode.com/"),
                DBMS.FIREBIRD: (FIREBIRD_ALIASES, "python-kinterbasdb", "http://kinterbasdb.sourceforge.net/"),
                DBMS.MAXDB: (MAXDB_ALIASES, None, None),
                DBMS.SYBASE: (SYBASE_ALIASES, "python-pymssql", "http://pymssql.sourceforge.net/"),
                DBMS.DB2: (DB2_ALIASES, "python ibm-db", "http://code.google.com/p/ibm-db/")
            }

USER_AGENT_ALIASES = ( "ua", "useragent", "user-agent" )
REFERER_ALIASES = ( "ref", "referer", "referrer" )
HOST_ALIASES = ( "host", )

FROM_DUMMY_TABLE = {
                        DBMS.ORACLE: " FROM DUAL",
                        DBMS.ACCESS: " FROM MSysAccessObjects",
                        DBMS.FIREBIRD: " FROM RDB$DATABASE",
                        DBMS.MAXDB: " FROM VERSIONS",
                        DBMS.DB2: " FROM SYSIBM.SYSDUMMY1"
                   }

SQL_STATEMENTS = {
                       "SQL SELECT statement":  (
                             "select ",
                             "show ",
                             " top ",
                             " distinct ",
                             " from ",
                             " from dual",
                             " where ",
                             " group by ",
                             " order by ",
                             " having ",
                             " limit ",
                             " offset ",
                             " union all ",
                             " rownum as ",
                             "(case ",          ),

                       "SQL data definition":   (
                             "create ",
                             "declare ",
                             "drop ",
                             "truncate ",
                             "alter ",          ),

                       "SQL data manipulation": (
                             "bulk ",
                             "insert ",
                             "update ",
                             "delete ",
                             "merge ",
                             "load ",           ),

                       "SQL data control":      (
                             "grant ",
                             "revoke ",         ),

                       "SQL data execution":    (
                             "exec ",
                             "execute ",        ),

                       "SQL transaction":       (
                             "start transaction ",
                             "begin work ",
                             "begin transaction ",
                             "commit ",
                             "rollback ",       ),
                     }

# items displayed in basic help (-h) output
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
                        "wizard"
                   )

# string representation for NULL value
NULL = "NULL"

# string representation for blank ('') value
BLANK = "<blank>"

# string representation for current database
CURRENT_DB = "CD"

# Regular expressions used for parsing error messages (--parse-errors)
ERROR_PARSING_REGEXES = (
                          r"<b>[^<]*(fatal|error|warning|exception)[^<]*</b>:?\s*(?P<result>.+?)<br\s*/?\s*>",
                          r"(?m)^(fatal|error|warning|exception):?\s*(?P<result>.+?)$",
                          r"<li>Error Type:<br>(?P<result>.+?)</li>",
                          r"error '[0-9a-f]{8}'((<[^>]+>)|\s)+(?P<result>[^<>]+)"
                        )

# Regular expression used for parsing charset info from meta html headers
META_CHARSET_REGEX = r'<meta http-equiv="?content-type"?[^>]+charset=(?P<result>[^">]+)'

# Regular expression used for parsing refresh info from meta html headers
META_REFRESH_REGEX = r'<meta http-equiv="?refresh"?[^>]+content="?[^">]+url=(?P<result>[^">]+)'

# Regular expression used for parsing empty fields in tested form data
EMPTY_FORM_FIELDS_REGEX = r'(?P<result>[^=]+=(&|\Z))'

# Regular expression for soap message recognition
SOAP_REGEX = r"\A(<\?xml[^>]+>)?\s*<soap.+</soap"

# Reference: http://www.cs.ru.nl/bachelorscripties/2010/Martin_Devillers___0437999___Analyzing_password_strength.pdf
COMMON_PASSWORD_SUFFIXES = ("1", "123", "2", "12", "3", "13", "7", "11", "5", "22", "23", "01", "4", "07", "21", "14", "10", "06", "08", "8", "15", "69", "16", "6", "18")

# Reference: http://www.the-interweb.com/serendipity/index.php?/archives/94-A-brief-analysis-of-40,000-leaked-MySpace-passwords.html
COMMON_PASSWORD_SUFFIXES += ("!", ".", "*", "!!", "?", ";", "..", "!!!", ",", "@")

# Splitter used between requests in WebScarab log files
WEBSCARAB_SPLITTER = "### Conversation"

# Splitter used between requests in BURP log files
BURP_REQUEST_REGEX = r"={10,}\s+[^=]+={10,}\s(.+?)\s={10,}"

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

# Maximum length used for retrieving data over MySQL error based payload due to "known" problems with longer result strings
MYSQL_ERROR_CHUNK_LENGTH = 50

# Maximum length used for retrieving data over MSSQL error based payload due to trimming problems with longer result strings
MSSQL_ERROR_CHUNK_LENGTH = 100

# Do not unescape the injected statement if it contains any of the following SQL words
EXCLUDE_UNESCAPE = ("WAITFOR DELAY ", " INTO DUMPFILE ", " INTO OUTFILE ", "CREATE ", "BULK ", "EXEC ", "RECONFIGURE ", "DECLARE ", "'%s'" % CHAR_INFERENCE_MARK)

# Mark used for replacement of reflected values
REFLECTED_VALUE_MARKER = "__REFLECTED_VALUE__"

# Regular expression used for replacing border non-alphanum characters
REFLECTED_BORDER_REGEX = r"[^A-Za-z]+"

# Regular expression used for replacing non-alphanum characters
REFLECTED_REPLACEMENT_REGEX = r".+?"

# Maximum number of alpha-numerical parts in reflected regex (for speed purposes)
REFLECTED_MAX_REGEX_PARTS = 10

# Chars which can be used as a failsafe values in case of too long URL encoding value
URLENCODE_FAILSAFE_CHARS = "()|,"

# Maximum length of urlencoded value after which failsafe procedure takes away
URLENCODE_CHAR_LIMIT = 2000

# Default schema for Microsoft SQL Server DBMS
DEFAULT_MSSQL_SCHEMA = "dbo"

# Display hash attack info every mod number of items
HASH_MOD_ITEM_DISPLAY = 11

# Maximum integer value
MAX_INT = sys.maxint

# Parameters to be ignored in detection phase (upper case)
IGNORE_PARAMETERS = ("__VIEWSTATE", "__EVENTARGUMENT", "__EVENTTARGET", "__EVENTVALIDATION", "ASPSESSIONID", "ASP.NET_SESSIONID", "JSESSIONID", "CFID", "CFTOKEN")

# Turn off resume console info to avoid potential slowdowns
TURN_OFF_RESUME_INFO_LIMIT = 20

# Strftime format for results file used in multiple target mode
RESULTS_FILE_FORMAT = "results-%m%d%Y_%I%M%p.csv"

# Official web page with the list of Python supported codecs
CODECS_LIST_PAGE = "http://docs.python.org/library/codecs.html#standard-encodings"

# Simple regular expression used to distinguish scalar from multiple-row commands (not sole condition)
SQL_SCALAR_REGEX = r"\A(SELECT(?!\s+DISTINCT\(?))?\s*\w*\("

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

# Chars used to quickly distinguish if the user provided tainted parameter values
DUMMY_SQL_INJECTION_CHARS = ";()'"

# Simple check against dummy users
DUMMY_USER_INJECTION = r"(?i)[^\w](AND|OR)\s+[^\s]+[=><]"

# Extensions skipped by crawler
CRAWL_EXCLUDE_EXTENSIONS = ("gif","jpg","jar","tif","bmp","war","ear","mpg","wmv","mpeg","scm","iso","dmp","dll","cab","so","avi","bin","exe","iso","tar","png","pdf","ps","mp3","zip","rar","gz")

# Template used for common table existence check
BRUTE_TABLE_EXISTS_TEMPLATE = "EXISTS(SELECT %d FROM %s)"

# Template used for common column existence check
BRUTE_COLUMN_EXISTS_TEMPLATE = "EXISTS(SELECT %s FROM %s)"

# Payload used for checking of existence of IDS/WAF (dummier the better)
IDS_WAF_CHECK_PAYLOAD = "AND 1=1 UNION ALL SELECT 1,2,3,table_name FROM information_schema.tables"

# Used for status representation in dictionary attack phase
ROTATING_CHARS = ('\\', '|', '|', '/', '-')

# Chunk length (in items) used by BigArray objects (only last chunk and cached one are held in memory)
BIGARRAY_CHUNK_LENGTH = 4096

# Only console display last n table rows
TRIM_STDOUT_DUMP_SIZE = 256

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

# Skip unforced HashDB flush requests below the threshold number of cached items
HASHDB_FLUSH_THRESHOLD = 32

# Unique milestone value used for forced deprecation of old HashDB values (e.g. when changing hash/pickle mechanism)
HASHDB_MILESTONE_VALUE = "cAWxkLYCQT"  # r5129 "".join(random.sample(string.letters, 10))

# Warn user of possible delay due to large page dump in full UNION query injections
LARGE_OUTPUT_THRESHOLD = 1024**2

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
DNS_BOUNDARIES_ALPHABET = re.sub("[a-fA-F]", "", string.letters)

# Connection chunk size (processing large responses in chunks to avoid MemoryError crashes - e.g. large table dump in full UNION/inband injections)
MAX_CONNECTION_CHUNK_SIZE = 10 * 1024 * 1024

# Mark used for trimming unnecessary content in large chunks
LARGE_CHUNK_TRIM_MARKER = "__TRIMMED_CONTENT__"

# Generic SQL comment formation
GENERIC_SQL_COMMENT = "-- "

# Threshold value for turning back on time auto-adjustment mechanism
VALID_TIME_CHARS_RUN_THRESHOLD = 100

# Check for empty columns only if table is sufficiently large
CHECK_ZERO_COLUMNS_THRESHOLD = 10

# Boldify all logger messages containing these "patterns"
BOLD_PATTERNS = ("' injectable", "might be injectable", "' is vulnerable", "is not injectable")

# Generic www root directory names
GENERIC_DOC_ROOT_DIRECTORY_NAMES = ("htdocs", "wwwroot", "www")
