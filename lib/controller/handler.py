#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.settings import MSSQL_ALIASES
from lib.core.settings import MYSQL_ALIASES
from lib.core.settings import ORACLE_ALIASES
from lib.core.settings import PGSQL_ALIASES
from lib.core.settings import SQLITE_ALIASES
from lib.core.settings import ACCESS_ALIASES
from lib.core.settings import FIREBIRD_ALIASES

from plugins.dbms.mssqlserver import MSSQLServerMap
from plugins.dbms.mysql import MySQLMap
from plugins.dbms.oracle import OracleMap
from plugins.dbms.postgresql import PostgreSQLMap
from plugins.dbms.sqlite import SQLiteMap
from plugins.dbms.access import AccessMap
from plugins.dbms.firebird import FirebirdMap

def setHandler():
    """
    Detect which is the target web application back-end database
    management system.
    """

    count     = 0
    dbmsNames = ( "MySQL", "Oracle", "PostgreSQL", "Microsoft SQL Server", "SQLite", "Microsoft Access", "Firebird" )
    dbmsMap   = (
                  ( MYSQL_ALIASES, MySQLMap ),
                  ( ORACLE_ALIASES, OracleMap ),
                  ( PGSQL_ALIASES, PostgreSQLMap ),
                  ( MSSQL_ALIASES, MSSQLServerMap ),
                  ( SQLITE_ALIASES, SQLiteMap ),
                  ( ACCESS_ALIASES, AccessMap ),
                  ( FIREBIRD_ALIASES, FirebirdMap ),
                )

    for dbmsAliases, dbmsEntry in dbmsMap:
        if conf.dbms and conf.dbms not in dbmsAliases:
            debugMsg  = "skipping test for %s" % dbmsNames[count]
            logger.debug(debugMsg)

            count += 1

            continue

        dbmsHandler = dbmsEntry()

        if dbmsHandler.checkDbms():
            if not conf.dbms or conf.dbms in dbmsAliases:
                kb.dbmsDetected = True

                return dbmsHandler

    return None
