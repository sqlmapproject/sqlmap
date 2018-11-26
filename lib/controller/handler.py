#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.data import conf
from lib.core.data import kb
from lib.core.dicts import DBMS_DICT
from lib.core.enums import DBMS
from lib.core.exception import SqlmapConnectionException
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
from lib.core.settings import HSQLDB_ALIASES
from lib.core.settings import H2_ALIASES
from lib.core.settings import INFORMIX_ALIASES
from lib.utils.sqlalchemy import SQLAlchemy

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
from plugins.dbms.hsqldb import HSQLDBMap
from plugins.dbms.hsqldb.connector import Connector as HSQLDBConn
from plugins.dbms.h2 import H2Map
from plugins.dbms.h2.connector import Connector as H2Conn
from plugins.dbms.informix import InformixMap
from plugins.dbms.informix.connector import Connector as InformixConn

def setHandler():
    """
    Detect which is the target web application back-end database
    management system.
    """

    items = [
        (DBMS.MYSQL, MYSQL_ALIASES, MySQLMap, MySQLConn),
        (DBMS.ORACLE, ORACLE_ALIASES, OracleMap, OracleConn),
        (DBMS.PGSQL, PGSQL_ALIASES, PostgreSQLMap, PostgreSQLConn),
        (DBMS.MSSQL, MSSQL_ALIASES, MSSQLServerMap, MSSQLServerConn),
        (DBMS.SQLITE, SQLITE_ALIASES, SQLiteMap, SQLiteConn),
        (DBMS.ACCESS, ACCESS_ALIASES, AccessMap, AccessConn),
        (DBMS.FIREBIRD, FIREBIRD_ALIASES, FirebirdMap, FirebirdConn),
        (DBMS.MAXDB, MAXDB_ALIASES, MaxDBMap, MaxDBConn),
        (DBMS.SYBASE, SYBASE_ALIASES, SybaseMap, SybaseConn),
        (DBMS.DB2, DB2_ALIASES, DB2Map, DB2Conn),
        (DBMS.HSQLDB, HSQLDB_ALIASES, HSQLDBMap, HSQLDBConn),
        (DBMS.H2, H2_ALIASES, H2Map, H2Conn),
        (DBMS.INFORMIX, INFORMIX_ALIASES, InformixMap, InformixConn),
    ]

    _ = max(_ if (conf.get("dbms") or Backend.getIdentifiedDbms() or kb.heuristicExtendedDbms or "").lower() in _[1] else None for _ in items)
    if _:
        items.remove(_)
        items.insert(0, _)

    for dbms, aliases, Handler, Connector in items:
        if conf.forceDbms:
            if conf.forceDbms.lower() not in aliases:
                continue
            else:
                kb.dbms = conf.dbms = conf.forceDbms = dbms

        if kb.dbmsFilter:
            if dbms not in kb.dbmsFilter:
                continue

        handler = Handler()
        conf.dbmsConnector = Connector()

        if conf.direct:
            exception = None
            dialect = DBMS_DICT[dbms][3]

            if dialect:
                try:
                    sqlalchemy = SQLAlchemy(dialect=dialect)
                    sqlalchemy.connect()

                    if sqlalchemy.connector:
                        conf.dbmsConnector = sqlalchemy
                except Exception, ex:
                    exception = ex

            if not dialect or exception:
                try:
                    conf.dbmsConnector.connect()
                except Exception, ex:
                    if exception:
                        raise exception
                    else:
                        if not isinstance(ex, NameError):
                            raise
                        else:
                            msg = "support for direct connection to '%s' is not available. " % dbms
                            msg += "Please rerun with '--dependencies'"
                            raise SqlmapConnectionException(msg)

        if conf.forceDbms == dbms or handler.checkDbms():
            if kb.resolutionDbms:
                conf.dbmsHandler = max(_ for _ in items if _[0] == kb.resolutionDbms)[2]()
                conf.dbmsHandler._dbms = kb.resolutionDbms
            else:
                conf.dbmsHandler = handler
                conf.dbmsHandler._dbms = dbms

            break
        else:
            conf.dbmsConnector = None

    # At this point back-end DBMS is correctly fingerprinted, no need
    # to enforce it anymore
    Backend.flushForcedDbms()
