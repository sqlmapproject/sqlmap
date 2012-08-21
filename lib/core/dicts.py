#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import DBMS
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

FIREBIRD_TYPES = {
                    "261":"BLOB",
                    "14":"CHAR",
                    "40":"CSTRING",
                    "11":"D_FLOAT",
                    "27":"DOUBLE",
                    "10":"FLOAT",
                    "16":"INT64",
                    "8":"INTEGER",
                    "9":"QUAD",
                    "7":"SMALLINT",
                    "12":"DATE",
                    "13":"TIME",
                    "35":"TIMESTAMP",
                    "37":"VARCHAR"
                }

SYBASE_TYPES = {
                    "14":"floatn",
                    "8":"float",
                    "15":"datetimn",
                    "12":"datetime",
                    "23":"real",
                    "28":"numericn",
                    "10":"numeric",
                    "27":"decimaln",
                    "26":"decimal",
                    "17":"moneyn",
                    "11":"money",
                    "21":"smallmoney",
                    "22":"smalldatetime",
                    "13":"intn",
                    "7":"int",
                    "6":"smallint",
                    "5":"tinyint",
                    "16":"bit",
                    "2":"varchar",
                    "18":"sysname",
                    "25":"nvarchar",
                    "1":"char",
                    "24":"nchar",
                    "4":"varbinary",
                    "80":"timestamp",
                    "3":"binary",
                    "19":"text",
                    "20":"image",
                }

MYSQL_PRIVS = {
                    1:"select_priv",
                    2:"insert_priv",
                    3:"update_priv",
                    4:"delete_priv",
                    5:"create_priv",
                    6:"drop_priv",
                    7:"reload_priv",
                    8:"shutdown_priv",
                    9:"process_priv",
                    10:"file_priv",
                    11:"grant_priv",
                    12:"references_priv",
                    13:"index_priv",
                    14:"alter_priv",
                    15:"show_db_priv",
                    16:"super_priv",
                    17:"create_tmp_table_priv",
                    18:"lock_tables_priv",
                    19:"execute_priv",
                    20:"repl_slave_priv",
                    21:"repl_client_priv",
                    22:"create_view_priv",
                    23:"show_view_priv",
                    24:"create_routine_priv",
                    25:"alter_routine_priv",
                    26:"create_user_priv",
                }

PGSQL_PRIVS = {
                    1:"createdb",
                    2:"super",
                    3:"catupd",
                }

FIREBIRD_PRIVS = {
                    "S": "SELECT",
                    "I": "INSERT",
                    "U": "UPDATE",
                    "D": "DELETE",
                    "R": "REFERENCES",
                    "E": "EXECUTE"
                }

DB2_PRIVS = {
                    1: "CONTROLAUTH",
                    2: "ALTERAUTH",
                    3: "DELETEAUTH",
                    4: "INDEXAUTH",
                    5: "INSERTAUTH",
                    6: "REFAUTH",
                    7: "SELECTAUTH",
                    8: "UPDATEAUTH"
           }

DUMP_REPLACEMENTS = {" ": NULL, "": BLANK}

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
