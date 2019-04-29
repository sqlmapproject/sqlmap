#!/usr/bin/env python

"""
vulnserver.py - Trivial SQLi vulnerable HTTP server (Note: for testing purposes)

Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import re
import sqlite3
import sys
import threading
import traceback

if sys.version_info >= (3, 0):
    from http.client import FOUND
    from http.client import INTERNAL_SERVER_ERROR
    from http.client import NOT_FOUND
    from http.client import OK
    from http.server import BaseHTTPRequestHandler
    from http.server import HTTPServer
    from socketserver import ThreadingMixIn
    from urllib.parse import parse_qs
    from urllib.parse import unquote_plus
else:
    from BaseHTTPServer import BaseHTTPRequestHandler
    from BaseHTTPServer import HTTPServer
    from httplib import FOUND
    from httplib import INTERNAL_SERVER_ERROR
    from httplib import NOT_FOUND
    from httplib import OK
    from SocketServer import ThreadingMixIn
    from urlparse import parse_qs
    from urllib import unquote_plus

SCHEMA = """
    CREATE TABLE users (
        id INTEGER,
        name TEXT,
        surname TEXT
    );
    INSERT INTO users (id, name, surname) VALUES (1, 'luther', 'blisset');
    INSERT INTO users (id, name, surname) VALUES (2, 'fluffy', 'bunny');
    INSERT INTO users (id, name, surname) VALUES (3, 'wu', '179ad45c6ce2cb97cf1029e212046e81');
    INSERT INTO users (id, name, surname) VALUES (4, 'sqlmap/1.0-dev (http://sqlmap.org)', 'user agent header');
    INSERT INTO users (id, name, surname) VALUES (5, NULL, 'nameisnull');
"""

LISTEN_ADDRESS = "localhost"
LISTEN_PORT = 8440

_conn = None
_cursor = None
_lock = None
_server = None

def init(quiet=False):
    global _conn
    global _cursor
    global _lock

    _conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    _cursor = _conn.cursor()
    _lock = threading.Lock()

    _cursor.executescript(SCHEMA)

    if quiet:
        global print

        def _(*args, **kwargs):
            pass

        print = _

class ThreadingServer(ThreadingMixIn, HTTPServer):
    def finish_request(self, *args, **kwargs):
        try:
            HTTPServer.finish_request(self, *args, **kwargs)
        except Exception:
            traceback.print_exc()

class ReqHandler(BaseHTTPRequestHandler):
    def do_REQUEST(self):
        path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
        params = {}

        if query:
            params.update(parse_qs(query))

            if "<script>" in unquote_plus(query):
                self.send_response(INTERNAL_SERVER_ERROR)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write("CLOUDFLARE_ERROR_500S_BOX".encode("utf8"))
                return

        if hasattr(self, "data"):
            params.update(parse_qs(self.data))

        for key in params:
            if params[key]:
                params[key] = params[key][-1]

        self.url, self.params = path, params

        if self.url == '/':
            if "id" not in params:
                self.send_response(FOUND)
                self.send_header("Connection", "close")
                self.send_header("Location", "/?id=1")
                self.end_headers()
            else:
                self.send_response(OK)
                self.send_header("Content-type", "text/html")
                self.send_header("Connection", "close")
                self.end_headers()

                try:
                    with _lock:
                        _cursor.execute("SELECT * FROM users WHERE id=%s LIMIT 0, 1" % self.params.get("id", ""))
                        results = _cursor.fetchall()

                    output = "<b>SQL results:</b>\n"
                    output += "<table border=\"1\">\n"
                    for row in results:
                        output += "<tr>"
                        for value in row:
                            output += "<td>%s</td>" % value
                        output += "</tr>\n"
                    output += "</table>\n"
                    output += "</body></html>"
                except Exception as ex:
                    output = "%s: %s" % (re.search(r"'([^']+)'", str(type(ex))).group(1), ex)

                self.wfile.write(output.encode("utf8"))
        else:
            self.send_response(NOT_FOUND)
            self.send_header("Connection", "close")
            self.end_headers()

    def do_GET(self):
        self.do_REQUEST()

    def do_POST(self):
        length = int(self.headers.get("Content-length", 0))
        if length:
            data = self.rfile.read(length)
            data = unquote_plus(data.decode("utf8"))
            self.data = data
        self.do_REQUEST()

    def log_message(self, format, *args):
        return

def run(address=LISTEN_ADDRESS, port=LISTEN_PORT):
    global _server
    try:
        _server = ThreadingServer((address, port), ReqHandler)
        print("[i] running HTTP server at '%s:%d'" % (address, port))
        _server.serve_forever()
    except KeyboardInterrupt:
        _server.socket.close()
        raise

if __name__ == "__main__":
    try:
        init()
        run(sys.argv[1] if len(sys.argv) > 1 else LISTEN_ADDRESS, int(sys.argv[2] if len(sys.argv) > 2 else LISTEN_PORT))
    except KeyboardInterrupt:
        print("\r[x] Ctrl-C received")
