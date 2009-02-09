#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

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



import logging
import os
import sys


# sqlmap version and site
VERSION            = "0.6.5-rc1"
VERSION_STRING     = "sqlmap/%s" % VERSION
SITE               = "http://sqlmap.sourceforge.net"

# sqlmap logger
logging.addLevelName(9, "TRAFFIC OUT")
logging.addLevelName(8, "TRAFFIC IN")
LOGGER             = logging.getLogger("sqlmapLog")
LOGGER_HANDLER     = logging.StreamHandler(sys.stdout)
FORMATTER          = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")

LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.WARN)

# Url to update Microsoft SQL Server XML versions file from
MSSQL_VERSIONS_URL = "http://www.sqlsecurity.com/FAQs/SQLServerVersionDatabase/tabid/63/Default.aspx"

# Url to update sqlmap from
SQLMAP_VERSION_URL = "%s/doc/VERSION" % SITE
SQLMAP_SOURCE_URL  = "http://downloads.sourceforge.net/sqlmap/sqlmap-%s.zip"

# Database managemen system specific variables
MSSQL_SYSTEM_DBS  = ( "Northwind", "model", "msdb", "pubs", "tempdb" )
MYSQL_SYSTEM_DBS  = ( "information_schema", "mysql" )                   # Before MySQL 5.0 only "mysql"
PGSQL_SYSTEM_DBS  = ( "information_schema", "pg_catalog" )
ORACLE_SYSTEM_DBS = ( "SYSTEM", "SYSAUX" )                              # These are TABLESPACE_NAME

MSSQL_ALIASES     = [ "microsoft sql server", "mssqlserver", "mssql", "ms" ]
MYSQL_ALIASES     = [ "mysql", "my" ]
PGSQL_ALIASES     = [ "postgresql", "postgres", "pgsql", "psql", "pg" ]
ORACLE_ALIASES    = [ "oracle", "orcl", "ora", "or" ]

SUPPORTED_DBMS    = MSSQL_ALIASES + MYSQL_ALIASES + PGSQL_ALIASES + ORACLE_ALIASES
SUPPORTED_OS      = ( "linux", "windows" )

# TODO: port to command line/configuration file options?
SECONDS           = 5
RETRIES           = 3

MATCH_RATIO       = None

SQL_STATEMENTS    = {
                      "SQL SELECT statement":  (
                             "select ",
                             "show ",
                             " top ",
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
                             "(case ",         ),

                      "SQL data definition":   (
                             "create ",
                             "drop ",
                             "truncate ",
                             "alter ",         ),

                      "SQL data manipulation": (
                             "insert ",
                             "update ",
                             "delete ",
                             "merge ",         ),

                      "SQL data control":      (
                             "grant ",         ),

                      "SQL data execution":    (
                             "exec ",
                             "execute ",       ),

                      "SQL transaction":       (
                             "start transaction ",
                             "begin work ",
                             "begin transaction ",
                             "commit ",
                             "rollback ",      ),
                    }
