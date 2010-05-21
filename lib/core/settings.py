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

import logging
import os
import subprocess
import sys

# sqlmap version and site
VERSION            = "0.9-dev"
VERSION_STRING     = "sqlmap/%s" % VERSION
DESCRIPTION        = "automatic SQL injection and database takeover tool"
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

# System variables
IS_WIN             = subprocess.mswindows
# The name of the operating system dependent module imported. The following
# names have currently been registered: 'posix', 'nt', 'mac', 'os2', 'ce',
# 'java', 'riscos'
PLATFORM           = os.name
PYVERSION          = sys.version.split()[0]

# Url to update Microsoft SQL Server XML versions file from
MSSQL_VERSIONS_URL = "http://www.sqlsecurity.com/FAQs/SQLServerVersionDatabase/tabid/63/Default.aspx"

# Database management system specific variables
MSSQL_SYSTEM_DBS   = ( "Northwind", "model", "msdb", "pubs", "tempdb" )
MYSQL_SYSTEM_DBS   = ( "information_schema", "mysql" )                   # Before MySQL 5.0 only "mysql"
PGSQL_SYSTEM_DBS   = ( "information_schema", "pg_catalog", "pg_toast" )
ORACLE_SYSTEM_DBS  = ( "SYSTEM", "SYSAUX" )                              # These are TABLESPACE_NAME
SQLITE_SYSTEM_DBS   = ( "sqlite_master", "sqlite_temp_master" )
ACCESS_SYSTEM_DBS   = ( "MSysAccessObjects", "MSysACEs", "MSysObjects", "MSysQueries", "MSysRelationships", "MSysAccessStorage",\
                        "MSysAccessXML", "MSysModules", "MSysModules2" )
FIREBIRD_SYSTEM_DBS = ( "RDB$BACKUP_HISTORY", "RDB$CHARACTER_SETS", "RDB$CHECK_CONSTRAINTS", "RDB$COLLATIONS", "RDB$DATABASE",\
                        "RDB$DEPENDENCIES", "RDB$EXCEPTIONS", "RDB$FIELDS", "RDB$FIELD_DIMENSIONS", " RDB$FILES", "RDB$FILTERS",\
                        "RDB$FORMATS", "RDB$FUNCTIONS", "RDB$FUNCTION_ARGUMENTS", "RDB$GENERATORS", "RDB$INDEX_SEGMENTS", "RDB$INDICES",\
                        "RDB$LOG_FILES", "RDB$PAGES", "RDB$PROCEDURES", "RDB$PROCEDURE_PARAMETERS", "RDB$REF_CONSTRAINTS", "RDB$RELATIONS",\
                        "RDB$RELATION_CONSTRAINTS", "RDB$RELATION_FIELDS", "RDB$ROLES", "RDB$SECURITY_CLASSES", "RDB$TRANSACTIONS", "RDB$TRIGGERS",\
                        "RDB$TRIGGER_MESSAGES", "RDB$TYPES", "RDB$USER_PRIVILEGES", "RDB$VIEW_RELATIONS" )

MSSQL_ALIASES      = [ "microsoft sql server", "mssqlserver", "mssql", "ms" ]
MYSQL_ALIASES      = [ "mysql", "my" ]
PGSQL_ALIASES      = [ "postgresql", "postgres", "pgsql", "psql", "pg" ]
ORACLE_ALIASES     = [ "oracle", "orcl", "ora", "or" ]
SQLITE_ALIASES     = [ "sqlite", "sqlite3" ]
ACCESS_ALIASES     = [ "access", "jet", "microsoft access", "msaccess" ]
FIREBIRD_ALIASES   = [ "firebird", "mozilla firebird", "interbase", "ibase", "fb" ]

SUPPORTED_DBMS     = MSSQL_ALIASES + MYSQL_ALIASES + PGSQL_ALIASES + ORACLE_ALIASES + SQLITE_ALIASES + ACCESS_ALIASES + FIREBIRD_ALIASES
SUPPORTED_OS       = ( "linux", "windows" )

SQL_STATEMENTS     = {
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
                             "(case ",         ),

                       "SQL data definition":   (
                             "create ",
                             "declare ",
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
                             " exec ",
                             "execute ",       ),

                       "SQL transaction":       (
                             "start transaction ",
                             "begin work ",
                             "begin transaction ",
                             "commit ",
                             "rollback ",      ),
                     }
