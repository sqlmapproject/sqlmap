#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
dbwire - minimal, dependency-free (stdlib-only) database wire-protocol clients used as a fallback for
sqlmap's direct ('-d') connection when no native driver (and no SQLAlchemy) is installed.

Design note: connectors speak a *wire protocol*, not a product, so a single client covers the whole
compatible family - e.g. the PostgreSQL client also serves CockroachDB, CrateDB, Redshift and Greenplum;
a MySQL client serves MariaDB/TiDB/Aurora; a TDS client serves MSSQL/Sybase. Each module exposes a small
PEP 249 (DB-API 2.0) subset (connect(), Connection.cursor()/commit()/close(), Cursor.execute()/fetchall()).
"""

__version__ = "0.1"

apilevel = "2.0"
threadsafety = 1
paramstyle = "pyformat"

# PEP 249 exception hierarchy (shared by every wire module)
class Error(Exception):
    pass

class InterfaceError(Error):
    pass

class DatabaseError(Error):
    pass

class OperationalError(DatabaseError):
    pass

class DataError(DatabaseError):
    pass

class IntegrityError(DatabaseError):
    pass

class ProgrammingError(DatabaseError):
    pass

class InternalError(DatabaseError):
    pass

class NotSupportedError(DatabaseError):
    pass
