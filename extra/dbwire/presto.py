#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
Minimal pure-python Presto/Trino client over its native HTTP/REST interface (stdlib only, no
presto-python-client). A query is POSTed to /v1/statement; the server returns JSON pages carrying
'columns'/'data' and a 'nextUri' to poll until the statement finishes. Both X-Presto-* and X-Trino-*
headers are sent so the same client works against Presto and Trino.
"""

import base64
import json
import socket

try:
    from urllib.request import Request, urlopen        # Python 3
    from urllib.error import HTTPError, URLError
except ImportError:
    from urllib2 import Request, urlopen, HTTPError, URLError  # Python 2

from extra.dbwire import InterfaceError
from extra.dbwire import NotSupportedError
from extra.dbwire import OperationalError
from extra.dbwire import ProgrammingError

def _convert(value, coltype):
    # normalize Presto/Trino JSON cells for sqlmap: VARBINARY arrives base64-encoded (decode to bytes so
    # direct()'s binary handling hex-encodes it), ARRAY/MAP/ROW arrive as JSON structures (serialize to text)
    if value is None:
        return value
    if coltype.startswith("varbinary"):
        try:
            return base64.b64decode(value)
        except Exception:
            return value
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return value

class Cursor(object):
    def __init__(self, connection):
        self.connection = connection
        self.description = None
        self.rowcount = -1
        self._rows = []
        self._pos = 0

    def execute(self, query, params=None):
        if params is not None:
            raise NotSupportedError("parameter binding is not supported; pass a fully-formed query string")
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
    def __init__(self, host, port, user, password, catalog, schema, timeout):
        self._statement_url = "http://%s:%d/v1/statement" % (host, port)
        self._timeout = timeout
        self._headers = {"Content-Type": "text/plain"}
        for prefix in ("X-Presto-", "X-Trino-"):
            self._headers[prefix + "User"] = user or "sqlmap"
            self._headers[prefix + "Source"] = "dbwire"
            # only send Catalog/Schema when supplied: a Schema without a Catalog makes Trino reject every
            # request ("Schema is set but catalog is not"), so never force a "default" schema
            if catalog:
                self._headers[prefix + "Catalog"] = catalog
            if schema:
                self._headers[prefix + "Schema"] = schema
        if password:
            token = base64.b64encode(("%s:%s" % (user or "", password)).encode("utf-8")).decode("ascii")
            self._headers["Authorization"] = "Basic %s" % token

    def cursor(self):
        return Cursor(self)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass  # HTTP is stateless

    def _request(self, url, data=None):
        req = Request(url, data=data.encode("utf-8") if data is not None else None, headers=self._headers)
        try:
            body = urlopen(req, timeout=self._timeout).read().decode("utf-8", "replace")
        except HTTPError as ex:
            raise ProgrammingError("(remote) HTTP %s: %s" % (ex.code, ex.read().decode("utf-8", "replace")[:200]))
        except URLError as ex:
            raise OperationalError("(remote) %s" % ex)
        except (socket.timeout, socket.error) as ex:
            raise OperationalError("(remote) %s" % ex)
        try:
            return json.loads(body)
        except ValueError as ex:
            raise InterfaceError("malformed server response: %s" % ex)

    def _query(self, query):
        page = self._request(self._statement_url, data=query)
        columns, rows, types = None, [], []
        while True:
            if page.get("error"):
                message = page["error"].get("message", "unknown error")
                raise ProgrammingError("(remote) %s" % message)
            if page.get("columns") and columns is None:
                columns = [(c.get("name"), c.get("type"), None, None, None, None, None) for c in page["columns"]]
                types = [(c.get("type") or "") for c in page["columns"]]
            for row in page.get("data") or []:
                rows.append(tuple(_convert(v, types[i] if i < len(types) else "") for i, v in enumerate(row)))
            next_uri = page.get("nextUri")
            if not next_uri:
                break
            page = self._request(next_uri)
        return columns, rows

def connect(host=None, port=8080, user=None, password=None, database=None, connect_timeout=None, schema=None, **kwargs):
    connection = Connection(host or "localhost", int(port or 8080), user, password, database, schema, connect_timeout)
    try:
        connection._query("SELECT 1")  # verify connectivity/credentials
    except ProgrammingError:
        raise
    except Exception as ex:
        raise OperationalError("could not connect to '%s:%s' (%s)" % (host, port, ex))
    return connection
