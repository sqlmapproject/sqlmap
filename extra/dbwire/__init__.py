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

def http_origin(host, port):
    """
    'http://host:port', with a literal IPv6 address bracketed as RFC 3986 requires. Without the brackets
    the colons in the address are parsed as the port separator and the URL is simply wrong.
    """

    host = host or "localhost"
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    return "http://%s:%d" % (host, int(port))


def connection_lost(ex):
    """
    Turn a raw socket/OS failure into the DB-API hierarchy above.

    Callers of a PEP 249 driver only ever catch Error and its subclasses, so a bare socket.error escaping
    from a send/recv leaves them with an unhandled traceback instead of a handled connection failure.
    """

    return OperationalError("connection lost (%s)" % ex)

def keepalive(sock):
    """
    Ask the kernel to probe an idle connection, so a peer that dies without a FIN is eventually detected.

    Deliberately NOT a read timeout: a legitimate query can take minutes on a big table, and a fixed
    deadline would kill it. Keepalive distinguishes a dead peer from a slow one, which is the actual
    failure being guarded against. Best-effort - the options are not portable everywhere.
    """

    import socket as _socket

    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_KEEPALIVE, 1)
        for name, value in (("TCP_KEEPIDLE", 60), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 5)):
            if hasattr(_socket, name):
                sock.setsockopt(_socket.IPPROTO_TCP, getattr(_socket, name), value)
    except Exception:
        pass
