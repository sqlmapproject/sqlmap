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
a MySQL client serves MariaDB/TiDB/Aurora. Where a family split the protocol, so does the client: tds.py
speaks Microsoft's TDS 7.x and sybase.py the TDS 5.0 that ASE kept. Each module exposes a small PEP 249
(DB-API 2.0) subset (connect(), Connection.cursor()/commit()/close(), Cursor.execute()/fetchall()).
"""

import socket

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

def handshake_done(sock):
    """
    Drop the connect deadline, once the login exchange is over.

    connect_timeout has to stay armed THROUGH the handshake, not just the TCP connect: a peer that
    accepts the connection and then says nothing (a wrong port, a silent proxy, a dropping firewall) is
    perfectly alive as far as keepalive() below is concerned, so an unbounded login read waits forever.
    A query is the opposite case - see keepalive().
    """

    try:
        sock.settimeout(None)
    except Exception:
        pass

def keepalive(sock):
    """
    Ask the kernel to probe an idle connection, so a peer that dies without a FIN is eventually detected.

    Deliberately NOT a read timeout: a legitimate query can take minutes on a big table, and a fixed
    deadline would kill it. Keepalive distinguishes a dead peer from a slow one, which is the actual
    failure being guarded against. Best-effort - the options are not portable everywhere.
    """

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for name, value in (("TCP_KEEPIDLE", 60), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 5)):
            if hasattr(socket, name):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, name), value)
    except Exception:
        pass

def recvn(sock, n):
    """
    Read exactly n bytes off `sock`, or raise - every wire protocol here is framed, so a short read is a
    desynchronized stream, not a smaller message.

    Shared because it was five identical copies: a fix to the recv loop has to land once, not per module.
    """

    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.error, OSError) as ex:
            raise connection_lost(ex)
        if not chunk:
            raise InterfaceError("connection closed by server")
        buf += chunk
    return buf
