#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import socket
import threading
import time

from lib.core.settings import KEEPALIVE_IDLE_TIMEOUT
from lib.core.settings import KEEPALIVE_MAX_REQUESTS
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import urllib as _urllib

# Note: prior to Python 2.4 it was the HTTP handler's job to decide what to handle
# specially; since 2.4 that belongs to HTTPErrorProcessor, hence everything is passed up
HANDLE_ERRORS = 0

class _ConnectionPool(threading.local):
    """
    Per-thread pool of reusable persistent connections.

    Keeping one connection per (scheme, host) and per worker thread is what
    keeps Keep-Alive safe under '--threads': a socket is never shared between
    threads, so concurrent requests can never interleave on the same wire (the
    classic cause of response desynchronization). Synchronous reuse within a
    single thread is fine because the previous response is always fully drained
    before the next request is issued (see L{_KeepAliveResponseMixin}).
    """

    def __init__(self):
        self.conns = {}  # key -> [connection, request_count, last_used]

class _KeepAliveHandler(object):
    def __init__(self):
        self._pool = _ConnectionPool()

    def _take(self, key):
        """
        Returns a (still usable) pooled connection for L{key} or None
        """

        entry = self._pool.conns.pop(key, None)

        if entry is not None:
            conn, count, last = entry
            if (time.time() - last) <= KEEPALIVE_IDLE_TIMEOUT and count < KEEPALIVE_MAX_REQUESTS:
                return conn, count

            # Too old or too heavily used; drop it
            try:
                conn.close()
            except Exception:
                pass

        return None, 0

    def _give_back(self, key, conn, count):
        self._pool.conns[key] = [conn, count, time.time()]

    def do_open(self, req):
        # Note: 'selector'/'host' attributes on Python 3 (Request.get_host() was deprecated since
        # 3.3 and removed in 3.12); the get_*() fallbacks are only reachable under Python 2
        host = req.host if hasattr(req, "host") else req.get_host()

        if not host:
            raise _urllib.error.URLError("no host given")

        key = "%s://%s" % (self._scheme, host)

        conn, count = self._take(key)
        reused = conn is not None

        try:
            if reused:
                # A pooled socket may have been closed by the server in the
                # meantime; treat any failure (or a bogus HTTP/0.9 reply, which
                # is httplib's tell-tale for a dead socket) as a stale connection
                try:
                    self._send_request(conn, req)
                    response = conn.getresponse()
                    if response is None or getattr(response, "version", 0) == 9:
                        raise _http_client.HTTPException("stale connection")
                except (socket.error, _http_client.HTTPException):
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = None
                    reused = False

            if conn is None:
                conn = self._get_connection(host)
                count = 0
                self._send_request(conn, req)
                response = conn.getresponse()
        except (socket.error, _http_client.HTTPException) as ex:
            raise _urllib.error.URLError(ex)

        count += 1

        # Honor an explicit 'Connection: close' even when L{will_close} wasn't set
        willClose = response.will_close
        if not willClose:
            try:
                headers = getattr(response, "msg", None) or getattr(response, "headers", None)
                value = headers.get("connection") or headers.get("Connection") if headers else None
                if value and "close" in value.lower():
                    willClose = True
            except Exception:
                pass

        keep = not willClose and count < KEEPALIVE_MAX_REQUESTS

        self._adapt(response, req.get_full_url())
        self._instrument(response, key, conn, count, keep)

        if response.status == 200 or not HANDLE_ERRORS:
            return response
        else:
            return self.parent.error("http", req, response, response.status, response.reason, response.headers)

    def _adapt(self, response, url):
        """
        Makes a raw httplib response indistinguishable from the object normally
        returned by C{urlopen} (the surface the rest of sqlmap relies on)
        """

        headers = getattr(response, "headers", None)
        if headers is None:
            headers = response.msg  # Python 2: msg holds the parsed headers

        response.url = url
        response.code = response.status
        response.headers = headers

        if not hasattr(response, "info"):
            response.info = lambda headers=headers: headers
        if not hasattr(response, "geturl"):
            response.geturl = lambda url=url: url
        if not hasattr(response, "getcode"):
            response.getcode = lambda response=response: response.status

        # Note: Python 2's httplib.HTTPResponse lacks readline()/readlines(), which urllib2's
        # error wrapping (addinfourl, for any non-2xx response) requires; provide them over read()
        if not hasattr(response, "readline"):
            response.readline = _makeReadline(response)
            response.readlines = _makeReadlines(response)

        # Note: must come last as on Python 3 'msg' initially aliases the headers
        response.msg = response.reason

    def _instrument(self, response, key, conn, count, keep):
        """
        Returns the connection to the pool once (and only once) its body has been
        fully consumed; otherwise the socket is closed. A partially read response
        (e.g. sqlmap hitting a size cap) leaves unread bytes on the wire, so such
        a connection is never reused.
        """

        state = {"handled": False}
        _read = response.read
        _close = response.close

        def drained():
            checker = getattr(response, "isclosed", None)
            if callable(checker):
                try:
                    return checker()
                except Exception:
                    return False
            return getattr(response, "fp", None) is None

        def settle():
            # Once (and only once) the body is fully drained, decide the socket's fate
            if state["handled"] or not drained():
                return
            state["handled"] = True
            if keep:
                self._give_back(key, conn, count)
            else:
                try:
                    conn.close()
                except Exception:
                    pass

        def read(*args, **kwargs):
            data = _read(*args, **kwargs)
            settle()
            return data

        def close():
            # Note: on Python 2 httplib.read() calls close() itself upon EOF
            _close()
            settle()
            if not state["handled"]:
                # Closed before the body was fully consumed; unsafe to reuse
                state["handled"] = True
                try:
                    conn.close()
                except Exception:
                    pass

        response.read = read
        response.close = close

class HTTPKeepAliveHandler(_KeepAliveHandler, _urllib.request.HTTPHandler):
    _scheme = "http"

    def __init__(self):
        _KeepAliveHandler.__init__(self)

    def http_open(self, req):
        return self.do_open(req)

    def _get_connection(self, host):
        return _http_client.HTTPConnection(host)

    def _send_request(self, conn, req):
        _sendRequest(conn, req)

class HTTPSKeepAliveHandler(_KeepAliveHandler, _urllib.request.HTTPSHandler):
    _scheme = "https"

    def __init__(self):
        _KeepAliveHandler.__init__(self)

    def https_open(self, req):
        return self.do_open(req)

    def _get_connection(self, host):
        # Note: reuses sqlmap's SSL-negotiating connection (lib/request/httpshandler.py)
        from lib.request.httpshandler import HTTPSConnection
        from lib.request.httpshandler import ssl
        return HTTPSConnection(host) if ssl else _http_client.HTTPSConnection(host)

    def _send_request(self, conn, req):
        _sendRequest(conn, req)

def _sendRequest(conn, req):
    """
    Issues L{req} on the (possibly reused) low-level connection L{conn}
    """

    data = getattr(req, "data", None)
    method = req.get_method() or ("POST" if data is not None else "GET")
    selector = req.selector if hasattr(req, "selector") else req.get_selector()

    try:
        conn.putrequest(method, selector, skip_host=req.has_header("Host"), skip_accept_encoding=req.has_header("Accept-encoding"))

        if data is not None:
            if not req.has_header("Content-type"):
                conn.putheader("Content-type", "application/x-www-form-urlencoded")
            if not req.has_header("Content-length"):
                conn.putheader("Content-length", "%d" % len(data))
    except (socket.error, _http_client.HTTPException) as ex:
        raise _urllib.error.URLError(ex)

    if not req.has_header("Connection"):
        conn.putheader("Connection", "keep-alive")

    for key, value in req.header_items():
        conn.putheader(key, value)

    conn.endheaders()

    if data is not None:
        conn.send(data)

def _makeReadline(response):
    """
    A buffered readline() over response.read() (Python 2 httplib.HTTPResponse lacks one)
    """

    buffer = {"data": b""}

    def readline(*args, **kwargs):
        while b"\n" not in buffer["data"]:
            chunk = response.read(8192)
            if not chunk:
                break
            buffer["data"] += chunk
        data = buffer["data"]
        index = data.find(b"\n")
        if index == -1:
            buffer["data"] = b""
            return data
        buffer["data"] = data[index + 1:]
        return data[:index + 1]

    return readline

def _makeReadlines(response):
    def readlines(*args, **kwargs):
        result = []
        while True:
            line = response.readline()
            if not line:
                break
            result.append(line)
        return result

    return readlines
