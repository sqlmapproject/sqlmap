#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import Backend
from lib.core.data import conf
from lib.core.data import logger
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import ORACLE_ALIASES
from lib.core.settings import PGSQL_ALIASES
from lib.core.settings import SQLITE_ALIASES
from lib.core.settings import ACCESS_ALIASES
from lib.core.settings import FIREBIRD_ALIASES
from lib.core.settings import MAXDB_ALIASES
from lib.core.settings import SYBASE_ALIASES
from lib.core.settings import DB2_ALIASES

from plugins.dbms.mssqlserver import MSSQLServerMap
from plugins.dbms.mssqlserver.connector import Connector as MSSQLServerConn
from plugins.dbms.mysql import MySQLMap
from plugins.dbms.mysql.connector import Connector as MySQLConn
from plugins.dbms.oracle import OracleMap
from plugins.dbms.oracle.connector import Connector as OracleConn
from plugins.dbms.postgresql import PostgreSQLMap
from plugins.dbms.postgresql.connector import Connector as PostgreSQLConn
from plugins.dbms.sqlite import SQLiteMap
from plugins.dbms.sqlite.connector import Connector as SQLiteConn
from plugins.dbms.access import AccessMap
from plugins.dbms.access.connector import Connector as AccessConn
from plugins.dbms.firebird import FirebirdMap
from plugins.dbms.firebird.connector import Connector as FirebirdConn
from plugins.dbms.maxdb import MaxDBMap
from plugins.dbms.maxdb.connector import Connector as MaxDBConn
from plugins.dbms.sybase import SybaseMap
from plugins.dbms.sybase.connector import Connector as SybaseConn
from plugins.dbms.db2 import DB2Map
from plugins.dbms.db2.connector import Connector as DB2Conn

def setHandler():
    """
    Detect which is the target web application back-end database
    management system.
    """

    items = [
                  ("MySQL", MYSQL_ALIASES, MySQLMap, MySQLConn),
                  ("Oracle", ORACLE_ALIASES, OracleMap, OracleConn),
                  ("PostgreSQL", PGSQL_ALIASES, PostgreSQLMap, PostgreSQLConn),
                  ("Microsoft SQL Server", MSSQL_ALIASES, MSSQLServerMap, MSSQLServerConn),
                  ("SQLite", SQLITE_ALIASES, SQLiteMap, SQLiteConn),
                  ("Microsoft Access", ACCESS_ALIASES, AccessMap, AccessConn),
                  ("Firebird", FIREBIRD_ALIASES, FirebirdMap, FirebirdConn),
                  ("SAP MaxDB", MAXDB_ALIASES, MaxDBMap, MaxDBConn),
                  ("Sybase", SYBASE_ALIASES, SybaseMap, SybaseConn),
                  ("IBM DB2", DB2_ALIASES, DB2Map, DB2Conn)
            ]

    _ = max(_ if (Backend.getIdentifiedDbms() or "").lower() in _[1] else None for _ in items)
    if _:
        items.remove(_)
        items.insert(0, _)

    for name, aliases, Handler, Connector in items:
        if conf.dbms and conf.dbms not in aliases:
            debugMsg = "skipping test for %s" % name
            logger.debug(debugMsg)
            continue

        handler = Handler()
        conf.dbmsConnector = Connector()

        if conf.direct:
            logger.debug("forcing timeout to 10 seconds")
            conf.timeout = 10
            conf.dbmsConnector.connect()

        if handler.checkDbms():
            conf.dbmsHandler = handler
            break
        else:
            conf.dbmsConnector = None

    # At this point back-end DBMS is correctly fingerprinted, no need
    # to enforce it anymore
    Backend.flushForcedDbms()
