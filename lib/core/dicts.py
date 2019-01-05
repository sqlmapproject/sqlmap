#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import CONTENT_TYPE
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.enums import POST_HINT
from lib.core.settings import BLANK
from lib.core.settings import NULL
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import PGSQL_ALIASES
from lib.core.settings import ORACLE_ALIASES
from lib.core.settings import SQLITE_ALIASES
from lib.core.settings import ACCESS_ALIASES
from lib.core.settings import FIREBIRD_ALIASES
from lib.core.settings import MAXDB_ALIASES
from lib.core.settings import SYBASE_ALIASES
from lib.core.settings import DB2_ALIASES
from lib.core.settings import HSQLDB_ALIASES
from lib.core.settings import H2_ALIASES
from lib.core.settings import INFORMIX_ALIASES

FIREBIRD_TYPES = {
    261: "BLOB",
    14: "CHAR",
    40: "CSTRING",
    11: "D_FLOAT",
    27: "DOUBLE",
    10: "FLOAT",
    16: "INT64",
    8: "INTEGER",
    9: "QUAD",
    7: "SMALLINT",
    12: "DATE",
    13: "TIME",
    35: "TIMESTAMP",
    37: "VARCHAR",
}

INFORMIX_TYPES = {
    0: "CHAR",
    1: "SMALLINT",
    2: "INTEGER",
    3: "FLOAT",
    4: "SMALLFLOAT",
    5: "DECIMAL",
    6: "SERIAL",
    7: "DATE",
    8: "MONEY",
    9: "NULL",
    10: "DATETIME",
    11: "BYTE",
    12: "TEXT",
    13: "VARCHAR",
    14: "INTERVAL",
    15: "NCHAR",
    16: "NVARCHAR",
    17: "INT8",
    18: "SERIAL8",
    19: "SET",
    20: "MULTISET",
    21: "LIST",
    22: "ROW (unnamed)",
    23: "COLLECTION",
    40: "Variable-length opaque type",
    41: "Fixed-length opaque type",
    43: "LVARCHAR",
    45: "BOOLEAN",
    52: "BIGINT",
    53: "BIGSERIAL",
    2061: "IDSSECURITYLABEL",
    4118: "ROW (named)",
}

SYBASE_TYPES = {
    14: "floatn",
    8: "float",
    15: "datetimn",
    12: "datetime",
    23: "real",
    28: "numericn",
    10: "numeric",
    27: "decimaln",
    26: "decimal",
    17: "moneyn",
    11: "money",
    21: "smallmoney",
    22: "smalldatetime",
    13: "intn",
    7: "int",
    6: "smallint",
    5: "tinyint",
    16: "bit",
    2: "varchar",
    18: "sysname",
    25: "nvarchar",
    1: "char",
    24: "nchar",
    4: "varbinary",
    80: "timestamp",
    3: "binary",
    19: "text",
    20: "image",
}

MYSQL_PRIVS = {
    1: "select_priv",
    2: "insert_priv",
    3: "update_priv",
    4: "delete_priv",
    5: "create_priv",
    6: "drop_priv",
    7: "reload_priv",
    8: "shutdown_priv",
    9: "process_priv",
    10: "file_priv",
    11: "grant_priv",
    12: "references_priv",
    13: "index_priv",
    14: "alter_priv",
    15: "show_db_priv",
    16: "super_priv",
    17: "create_tmp_table_priv",
    18: "lock_tables_priv",
    19: "execute_priv",
    20: "repl_slave_priv",
    21: "repl_client_priv",
    22: "create_view_priv",
    23: "show_view_priv",
    24: "create_routine_priv",
    25: "alter_routine_priv",
    26: "create_user_priv",
}

PGSQL_PRIVS = {
    1: "createdb",
    2: "super",
    3: "catupd",
}

# Reference(s): http://stackoverflow.com/a/17672504
#               http://docwiki.embarcadero.com/InterBase/XE7/en/RDB$USER_PRIVILEGES

FIREBIRD_PRIVS = {
    "S": "SELECT",
    "I": "INSERT",
    "U": "UPDATE",
    "D": "DELETE",
    "R": "REFERENCE",
    "X": "EXECUTE",
    "A": "ALL",
    "M": "MEMBER",
    "T": "DECRYPT",
    "E": "ENCRYPT",
    "B": "SUBSCRIBE",
}

# Reference(s): https://www.ibm.com/support/knowledgecenter/SSGU8G_12.1.0/com.ibm.sqls.doc/ids_sqs_0147.htm
#               https://www.ibm.com/support/knowledgecenter/SSGU8G_11.70.0/com.ibm.sqlr.doc/ids_sqr_077.htm

INFORMIX_PRIVS = {
    "D": "DBA (all privileges)",
    "R": "RESOURCE (create UDRs, UDTs, permanent tables and indexes)",
    "C": "CONNECT (work with existing tables)",
    "G": "ROLE",
    "U": "DEFAULT (implicit connection)",
}

DB2_PRIVS = {
    1: "CONTROLAUTH",
    2: "ALTERAUTH",
    3: "DELETEAUTH",
    4: "INDEXAUTH",
    5: "INSERTAUTH",
    6: "REFAUTH",
    7: "SELECTAUTH",
    8: "UPDATEAUTH",
}

DUMP_REPLACEMENTS = {" ": NULL, "": BLANK}

DBMS_DICT = {
    DBMS.MSSQL: (MSSQL_ALIASES, "python-pymssql", "https://github.com/pymssql/pymssql", "mssql+pymssql"),
    DBMS.MYSQL: (MYSQL_ALIASES, "python-pymysql", "https://github.com/PyMySQL/PyMySQL", "mysql"),
    DBMS.PGSQL: (PGSQL_ALIASES, "python-psycopg2", "http://initd.org/psycopg/", "postgresql"),
    DBMS.ORACLE: (ORACLE_ALIASES, "python cx_Oracle", "https://oracle.github.io/python-cx_Oracle/", "oracle"),
    DBMS.SQLITE: (SQLITE_ALIASES, "python-sqlite", "https://docs.python.org/2/library/sqlite3.html", "sqlite"),
    DBMS.ACCESS: (ACCESS_ALIASES, "python-pyodbc", "https://github.com/mkleehammer/pyodbc", "access"),
    DBMS.FIREBIRD: (FIREBIRD_ALIASES, "python-kinterbasdb", "http://kinterbasdb.sourceforge.net/", "firebird"),
    DBMS.MAXDB: (MAXDB_ALIASES, None, None, "maxdb"),
    DBMS.SYBASE: (SYBASE_ALIASES, "python-pymssql", "https://github.com/pymssql/pymssql", "sybase"),
    DBMS.DB2: (DB2_ALIASES, "python ibm-db", "https://github.com/ibmdb/python-ibmdb", "ibm_db_sa"),
    DBMS.HSQLDB: (HSQLDB_ALIASES, "python jaydebeapi & python-jpype", "https://pypi.python.org/pypi/JayDeBeApi/ & http://jpype.sourceforge.net/", None),
    DBMS.H2: (H2_ALIASES, None, None, None),
    DBMS.INFORMIX: (INFORMIX_ALIASES, "python ibm-db", "https://github.com/ibmdb/python-ibmdb", "ibm_db_sa"),
}

FROM_DUMMY_TABLE = {
    DBMS.ORACLE: " FROM DUAL",
    DBMS.ACCESS: " FROM MSysAccessObjects",
    DBMS.FIREBIRD: " FROM RDB$DATABASE",
    DBMS.MAXDB: " FROM VERSIONS",
    DBMS.DB2: " FROM SYSIBM.SYSDUMMY1",
    DBMS.HSQLDB: " FROM INFORMATION_SCHEMA.SYSTEM_USERS",
    DBMS.INFORMIX: " FROM SYSMASTER:SYSDUAL"
}

SQL_STATEMENTS = {
    "SQL SELECT statement": (
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
        "(case ",
    ),

    "SQL data definition": (
        "create ",
        "declare ",
        "drop ",
        "truncate ",
        "alter ",
    ),

    "SQL data manipulation": (
        "bulk ",
        "insert ",
        "update ",
        "delete ",
        "merge ",
        "load ",
    ),

    "SQL data control": (
        "grant ",
        "revoke ",
    ),

    "SQL data execution": (
        "exec ",
        "execute ",
        "values ",
        "call ",
    ),

    "SQL transaction": (
        "start transaction ",
        "begin work ",
        "begin transaction ",
        "commit ",
        "rollback ",
    ),

    "SQL administration": (
        "set ",
    ),
}

POST_HINT_CONTENT_TYPES = {
    POST_HINT.JSON: "application/json",
    POST_HINT.JSON_LIKE: "application/json",
    POST_HINT.MULTIPART: "multipart/form-data",
    POST_HINT.SOAP: "application/soap+xml",
    POST_HINT.XML: "application/xml",
    POST_HINT.ARRAY_LIKE: "application/x-www-form-urlencoded; charset=utf-8",
}

DEPRECATED_OPTIONS = {
    "--replicate": "use '--dump-format=SQLITE' instead",
    "--no-unescape": "use '--no-escape' instead",
    "--binary": "use '--binary-fields' instead",
    "--auth-private": "use '--auth-file' instead",
    "--ignore-401": "use '--ignore-code' instead",
    "--second-order": "use '--second-url' instead",
    "--purge-output": "use '--purge' instead",
    "--check-payload": None,
    "--check-waf": None,
    "--pickled-options": "use '--api -c ...' instead",
}

DUMP_DATA_PREPROCESS = {
    DBMS.ORACLE: {"XMLTYPE": "(%s).getStringVal()"},  # Reference: https://www.tibcommunity.com/docs/DOC-3643
    DBMS.MSSQL: {"IMAGE": "CONVERT(VARBINARY(MAX),%s)"},
}

DEFAULT_DOC_ROOTS = {
    OS.WINDOWS: ("C:/xampp/htdocs/", "C:/wamp/www/", "C:/Inetpub/wwwroot/"),
    OS.LINUX: ("/var/www/", "/var/www/html", "/usr/local/apache2/htdocs", "/var/www/nginx-default", "/srv/www")  # Reference: https://wiki.apache.org/httpd/DistrosDefaultLayout
}

PART_RUN_CONTENT_TYPES = {
    "checkDbms": CONTENT_TYPE.TECHNIQUES,
    "getFingerprint": CONTENT_TYPE.DBMS_FINGERPRINT,
    "getBanner": CONTENT_TYPE.BANNER,
    "getCurrentUser": CONTENT_TYPE.CURRENT_USER,
    "getCurrentDb": CONTENT_TYPE.CURRENT_DB,
    "getHostname": CONTENT_TYPE.HOSTNAME,
    "isDba": CONTENT_TYPE.IS_DBA,
    "getUsers": CONTENT_TYPE.USERS,
    "getPasswordHashes": CONTENT_TYPE.PASSWORDS,
    "getPrivileges": CONTENT_TYPE.PRIVILEGES,
    "getRoles": CONTENT_TYPE.ROLES,
    "getDbs": CONTENT_TYPE.DBS,
    "getTables": CONTENT_TYPE.TABLES,
    "getColumns": CONTENT_TYPE.COLUMNS,
    "getSchema": CONTENT_TYPE.SCHEMA,
    "getCount": CONTENT_TYPE.COUNT,
    "dumpTable": CONTENT_TYPE.DUMP_TABLE,
    "search": CONTENT_TYPE.SEARCH,
    "sqlQuery": CONTENT_TYPE.SQL_QUERY,
    "tableExists": CONTENT_TYPE.COMMON_TABLES,
    "columnExists": CONTENT_TYPE.COMMON_COLUMNS,
    "readFile": CONTENT_TYPE.FILE_READ,
    "writeFile": CONTENT_TYPE.FILE_WRITE,
    "osCmd": CONTENT_TYPE.OS_CMD,
    "regRead": CONTENT_TYPE.REG_READ
}
