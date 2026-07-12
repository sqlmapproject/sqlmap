#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
Minimal pure-python ClickHouse client over its native HTTP interface (stdlib only, no clickhouse_connect).

ClickHouse exposes an HTTP endpoint that runs a query in the request body and streams the result back in a
chosen format; we use TabSeparatedWithNames (first line = column names, then tab-separated rows with
backslash escaping and \\N for NULL). Covers ClickHouse and its HTTP-compatible forks.
"""

import base64

try:
    from urllib.request import Request, urlopen        # Python 3
    from urllib.error import HTTPError, URLError
except ImportError:
    from urllib2 import Request, urlopen, HTTPError, URLError  # Python 2

from extra.dbwire import OperationalError
from extra.dbwire import ProgrammingError

def _unescape(value):
    if value == "\\N":
        return None
    if "\\" not in value:
        return value
    out, it = [], iter(range(len(value)))
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == "\\" and i + 1 < n:
            nxt = value[i + 1]
            out.append({"t": "\t", "n": "\n", "r": "\r", "0": "\0", "\\": "\\", "'": "'"}.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)

class Cursor(object):
    def __init__(self, connection):
        self.connection = connection
        self.description = None
        self.rowcount = -1
        self._rows = []
        self._pos = 0

    def execute(self, query, params=None):
        if params is not None:
            raise ProgrammingError("parameter binding is not supported; pass a fully-formed query string")
        self.description, self.rowcount, self._rows, self._pos = None, -1, [], 0
        self.description, self._rows = self.connection._query(query)
        self.rowcount = len(self._rows)
        return self

    def fetchall(self):
        retVal = self._rows[self._pos:]
        self._pos = len(self._rows)
        return retVal

    def fetchone(self):
        if self._pos >= len(self._rows):
            return None
        retVal = self._rows[self._pos]
        self._pos += 1
        return retVal

    def close(self):
        self._rows = []

class Connection(object):
    def __init__(self, host, port, user, password, database, timeout):
        self._url = "http://%s:%d/?database=%s&default_format=TabSeparatedWithNames" % (host, port, database or "default")
        self._headers = {}
        if user or password:
            token = base64.b64encode(("%s:%s" % (user or "", password or "")).encode("utf-8")).decode("ascii")
            self._headers["Authorization"] = "Basic %s" % token
        self._timeout = timeout

    def cursor(self):
        return Cursor(self)

    def commit(self):
        pass  # ClickHouse statements are executed immediately (no client-side transaction)

    def rollback(self):
        pass

    def close(self):
        pass  # HTTP is stateless

    def _query(self, query):
        req = Request(self._url, data=query.encode("utf-8"), headers=self._headers)
        try:
            body = urlopen(req, timeout=self._timeout).read().decode("utf-8", "replace")
        except HTTPError as ex:
            raise ProgrammingError("(remote) %s" % ex.read().decode("utf-8", "replace").strip())
        except URLError as ex:
            raise OperationalError("(remote) %s" % ex)

        if not body:
            return None, []
        lines = body.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        if not lines:
            return None, []
        description = [(name, None, None, None, None, None, None) for name in (_unescape(_) for _ in lines[0].split("\t"))]
        rows = [tuple(_unescape(_) for _ in line.split("\t")) for line in lines[1:]]
        return description, rows

def connect(host=None, port=8123, user=None, password=None, database=None, connect_timeout=None, **kwargs):
    connection = Connection(host or "localhost", int(port or 8123), user, password, database, connect_timeout)
    try:
        connection._query("SELECT 1")  # verify connectivity/credentials up front
    except ProgrammingError:
        raise
    except Exception as ex:
        raise OperationalError("could not connect to '%s:%s' (%s)" % (host, port, ex))
    return connection
