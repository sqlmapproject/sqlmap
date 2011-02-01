#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.datatype import advancedDict
from lib.core.enums import DBMS
from lib.core.settings import LOGGER
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import PGSQL_ALIASES
from lib.core.settings import ORACLE_ALIASES
from lib.core.settings import SQLITE_ALIASES
from lib.core.settings import ACCESS_ALIASES
from lib.core.settings import FIREBIRD_ALIASES
from lib.core.settings import MAXDB_ALIASES
from lib.core.settings import SYBASE_ALIASES

# sqlmap paths
paths = advancedDict()

# object to store original command line options
cmdLineOptions = advancedDict()

# object to share within function and classes command
# line options and settings
conf = advancedDict()

# object to share within function and classes results
kb = advancedDict()

# object with each database management system specific queries
queries = {}

# logger
logger = LOGGER

dbmsDict = { DBMS.MSSQL: [MSSQL_ALIASES, "python-pymssql", "http://pymssql.sourceforge.net/"],
             DBMS.MYSQL: [MYSQL_ALIASES, "python-mysqldb", "http://mysql-python.sourceforge.net/"],
             DBMS.PGSQL: [PGSQL_ALIASES, "python-psycopg2", "http://initd.org/psycopg/"],
             DBMS.ORACLE: [ORACLE_ALIASES, "python cx_Oracle", "http://cx-oracle.sourceforge.net/"],
             DBMS.SQLITE: [SQLITE_ALIASES, "python-pysqlite2", "http://pysqlite.googlecode.com/"],
             DBMS.ACCESS: [ACCESS_ALIASES, "python-pyodbc", "http://pyodbc.googlecode.com/"],
             DBMS.FIREBIRD: [FIREBIRD_ALIASES, "python-kinterbasdb", "http://kinterbasdb.sourceforge.net/"],
             DBMS.MAXDB: [MAXDB_ALIASES, None, None],
             DBMS.SYBASE: [SYBASE_ALIASES, "python-pymssql", "http://pymssql.sourceforge.net/"]
            }
