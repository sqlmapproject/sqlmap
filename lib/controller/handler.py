#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import getSafeExString
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import kb
from lib.core.dicts import DBMS_DICT
from lib.core.enums import DBMS
from lib.core.exception import SqlmapConnectionException
from lib.core.settings import ACCESS_ALIASES
from lib.core.settings import ALTIBASE_ALIASES
from lib.core.settings import CACHE_ALIASES
from lib.core.settings import CLICKHOUSE_ALIASES
from lib.core.settings import CRATEDB_ALIASES
from lib.core.settings import CUBRID_ALIASES
from lib.core.settings import DB2_ALIASES
from lib.core.settings import DERBY_ALIASES
from lib.core.settings import EXTREMEDB_ALIASES
from lib.core.settings import FIREBIRD_ALIASES
from lib.core.settings import FRONTBASE_ALIASES
from lib.core.settings import H2_ALIASES
from lib.core.settings import HSQLDB_ALIASES
from lib.core.settings import INFORMIX_ALIASES
from lib.core.settings import MAXDB_ALIASES
from lib.core.settings import MCKOI_ALIASES
from lib.core.settings import MIMERSQL_ALIASES
from lib.core.settings import MONETDB_ALIASES
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import ORACLE_ALIASES
from lib.core.settings import PGSQL_ALIASES
from lib.core.settings import PRESTO_ALIASES
from lib.core.settings import RAIMA_ALIASES
from lib.core.settings import SQLITE_ALIASES
from lib.core.settings import SYBASE_ALIASES
from lib.core.settings import VERTICA_ALIASES
from lib.core.settings import VIRTUOSO_ALIASES
from lib.core.settings import SNOWFLAKE_ALIASES
from lib.utils.sqlalchemy import SQLAlchemy

from plugins.dbms.access import AccessMap
from plugins.dbms.altibase import AltibaseMap
from plugins.dbms.cache import CacheMap
from plugins.dbms.clickhouse import ClickHouseMap
from plugins.dbms.cratedb import CrateDBMap
from plugins.dbms.cubrid import CubridMap
from plugins.dbms.db2 import DB2Map
from plugins.dbms.derby import DerbyMap
from plugins.dbms.extremedb import ExtremeDBMap
from plugins.dbms.firebird import FirebirdMap
from plugins.dbms.frontbase import FrontBaseMap
from plugins.dbms.h2 import H2Map
from plugins.dbms.hsqldb import HSQLDBMap
from plugins.dbms.informix import InformixMap
from plugins.dbms.maxdb import MaxDBMap
from plugins.dbms.mckoi import MckoiMap
from plugins.dbms.mimersql import MimerSQLMap
from plugins.dbms.monetdb import MonetDBMap
from plugins.dbms.mssqlserver import MSSQLServerMap
from plugins.dbms.mysql import MySQLMap
from plugins.dbms.oracle import OracleMap
from plugins.dbms.postgresql import PostgreSQLMap
from plugins.dbms.presto import PrestoMap
from plugins.dbms.raima import RaimaMap
from plugins.dbms.sqlite import SQLiteMap
from plugins.dbms.sybase import SybaseMap
from plugins.dbms.vertica import VerticaMap
from plugins.dbms.virtuoso import VirtuosoMap
from plugins.dbms.snowflake import SnowflakeMap

def setHandler():
    """
    Detect which is the target web application back-end database
    management system.
    """

    items = [
        (DBMS.MYSQL, MYSQL_ALIASES, MySQLMap, "plugins.dbms.mysql.connector"),
        (DBMS.ORACLE, ORACLE_ALIASES, OracleMap, "plugins.dbms.oracle.connector"),
        (DBMS.PGSQL, PGSQL_ALIASES, PostgreSQLMap, "plugins.dbms.postgresql.connector"),
        (DBMS.MSSQL, MSSQL_ALIASES, MSSQLServerMap, "plugins.dbms.mssqlserver.connector"),
        (DBMS.SQLITE, SQLITE_ALIASES, SQLiteMap, "plugins.dbms.sqlite.connector"),
        (DBMS.ACCESS, ACCESS_ALIASES, AccessMap, "plugins.dbms.access.connector"),
        (DBMS.FIREBIRD, FIREBIRD_ALIASES, FirebirdMap, "plugins.dbms.firebird.connector"),
        (DBMS.MAXDB, MAXDB_ALIASES, MaxDBMap, "plugins.dbms.maxdb.connector"),
        (DBMS.SYBASE, SYBASE_ALIASES, SybaseMap, "plugins.dbms.sybase.connector"),
        (DBMS.DB2, DB2_ALIASES, DB2Map, "plugins.dbms.db2.connector"),
        (DBMS.HSQLDB, HSQLDB_ALIASES, HSQLDBMap, "plugins.dbms.hsqldb.connector"),
        (DBMS.H2, H2_ALIASES, H2Map, "plugins.dbms.h2.connector"),
        (DBMS.INFORMIX, INFORMIX_ALIASES, InformixMap, "plugins.dbms.informix.connector"),
        (DBMS.MONETDB, MONETDB_ALIASES, MonetDBMap, "plugins.dbms.monetdb.connector"),
        (DBMS.DERBY, DERBY_ALIASES, DerbyMap, "plugins.dbms.derby.connector"),
        (DBMS.VERTICA, VERTICA_ALIASES, VerticaMap, "plugins.dbms.vertica.connector"),
        (DBMS.MCKOI, MCKOI_ALIASES, MckoiMap, "plugins.dbms.mckoi.connector"),
        (DBMS.PRESTO, PRESTO_ALIASES, PrestoMap, "plugins.dbms.presto.connector"),
        (DBMS.ALTIBASE, ALTIBASE_ALIASES, AltibaseMap, "plugins.dbms.altibase.connector"),
        (DBMS.MIMERSQL, MIMERSQL_ALIASES, MimerSQLMap, "plugins.dbms.mimersql.connector"),
        (DBMS.CLICKHOUSE, CLICKHOUSE_ALIASES, ClickHouseMap, "plugins.dbms.clickhouse.connector"),
        (DBMS.CRATEDB, CRATEDB_ALIASES, CrateDBMap, "plugins.dbms.cratedb.connector"),
        (DBMS.CUBRID, CUBRID_ALIASES, CubridMap, "plugins.dbms.cubrid.connector"),
        (DBMS.CACHE, CACHE_ALIASES, CacheMap, "plugins.dbms.cache.connector"),
        (DBMS.EXTREMEDB, EXTREMEDB_ALIASES, ExtremeDBMap, "plugins.dbms.extremedb.connector"),
        (DBMS.FRONTBASE, FRONTBASE_ALIASES, FrontBaseMap, "plugins.dbms.frontbase.connector"),
        (DBMS.RAIMA, RAIMA_ALIASES, RaimaMap, "plugins.dbms.raima.connector"),
        (DBMS.VIRTUOSO, VIRTUOSO_ALIASES, VirtuosoMap, "plugins.dbms.virtuoso.connector"),
        (DBMS.SNOWFLAKE, SNOWFLAKE_ALIASES, SnowflakeMap, "plugins.dbms.snowflake.connector"),
    ]

    _ = max(_ if (conf.get("dbms") or Backend.getIdentifiedDbms() or kb.heuristicExtendedDbms or "").lower() in _[1] else () for _ in items)
    if _:
        items.remove(_)
        items.insert(0, _)

    for dbms, aliases, Handler, connector in items:
        if conf.forceDbms:
            if conf.forceDbms.lower() not in aliases:
                continue
            else:
                kb.dbms = conf.dbms = conf.forceDbms = dbms

        if kb.dbmsFilter:
            if dbms not in kb.dbmsFilter:
                continue

        handler = Handler()
        conf.dbmsConnector = None

        if conf.direct:
            _ = __import__(connector, fromlist=['Connector'])
            conf.dbmsConnector = _.Connector()

            exception = None
            dialect = DBMS_DICT[dbms][3]

            if dialect:
                try:
                    sqlalchemy = SQLAlchemy(dialect=dialect)
                    sqlalchemy.connect()

                    if sqlalchemy.connector:
                        conf.dbmsConnector = sqlalchemy
                except Exception as ex:
                    exception = ex

            if not dialect or exception:
                try:
                    conf.dbmsConnector.connect()
                except NameError:
                    if exception:
                        raise exception
                    else:
                        msg = "support for direct connection to '%s' is not available. " % dbms
                        msg += "Please rerun with '--dependencies'"
                        raise SqlmapConnectionException(msg)
                except:
                    if exception:
                        singleTimeWarnMessage(getSafeExString(exception))
                    raise

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
