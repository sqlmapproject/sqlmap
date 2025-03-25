#!/usr/bin/env python

"""
vulnserver.py - Trivial SQLi vulnerable HTTP server (Note: for testing purposes)

Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import base64
import json
import re
import sqlite3
import sys
import threading
import traceback

PY3 = sys.version_info >= (3, 0)
UNICODE_ENCODING = "utf-8"
DEBUG = False

if PY3:
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
        surname TEXT,
        PRIMARY KEY (id)
    );
    INSERT INTO users (id, name, surname) VALUES (1, 'luther', 'blisset');
    INSERT INTO users (id, name, surname) VALUES (2, 'fluffy', 'bunny');
    INSERT INTO users (id, name, surname) VALUES (3, 'wu', '179ad45c6ce2cb97cf1029e212046e81');
    INSERT INTO users (id, name, surname) VALUES (4, 'sqlmap/1.0-dev (https://sqlmap.org)', 'user agent header');
    INSERT INTO users (id, name, surname) VALUES (5, NULL, 'nameisnull');
"""

LISTEN_ADDRESS = "localhost"
LISTEN_PORT = 8440

_conn = None
_cursor = None
_lock = None
_server = None
_alive = False

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
            if DEBUG:
                traceback.print_exc()

class ReqHandler(BaseHTTPRequestHandler):
    def do_REQUEST(self):
        path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
        params = {}

        if query:
            params.update(parse_qs(query))

            if "<script>" in unquote_plus(query):
                self.send_response(INTERNAL_SERVER_ERROR)
                self.send_header("X-Powered-By", "Express")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write("CLOUDFLARE_ERROR_500S_BOX".encode(UNICODE_ENCODING))
                return

        if hasattr(self, "data"):
            if self.data.startswith('{') and self.data.endswith('}'):
                params.update(json.loads(self.data))
            elif self.data.startswith('<') and self.data.endswith('>'):
                params.update(dict((_[0], _[1].replace("&apos;", "'").replace("&quot;", '"').replace("&lt;", '<').replace("&gt;", '>').replace("&amp;", '&')) for _ in re.findall(r'name="([^"]+)" value="([^"]*)"', self.data)))
            else:
                self.data = self.data.replace(';', '&')     # Note: seems that Python3 started ignoring parameter splitting with ';'
                params.update(parse_qs(self.data))

        for name in self.headers:
            params[name.lower()] = self.headers[name]

        if "cookie" in params:
            for part in params["cookie"].split(';'):
                part = part.strip()
                if '=' in part:
                    name, value = part.split('=', 1)
                    params[name.strip()] = unquote_plus(value.strip())

        for key in params:
            if params[key] and isinstance(params[key], (tuple, list)):
                params[key] = params[key][-1]

        self.url, self.params = path, params

        if self.url == '/':
            if not any(_ in self.params for _ in ("id", "query")):
                self.send_response(OK)
                self.send_header("Content-type", "text/html; charset=%s" % UNICODE_ENCODING)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"<!DOCTYPE html><html><head><title>vulnserver</title></head><body><h3>GET:</h3><a href='/?id=1'>link</a><hr><h3>POST:</h3><form method='post'>ID: <input type='text' name='id'><input type='submit' value='Submit'></form></body></html>")
            else:
                code, output = OK, ""

                try:
                    if self.params.get("echo", ""):
                        output += "%s<br>" % self.params["echo"]

                    if self.params.get("reflect", ""):
                        output += "%s<br>" % self.params.get("id")

                    with _lock:
                        if "query" in self.params:
                            _cursor.execute(self.params["query"])
                        elif "id" in self.params:
                            if "base64" in self.params:
                                _cursor.execute("SELECT * FROM users WHERE id=%s LIMIT 0, 1" % base64.b64decode("%s===" % self.params["id"], altchars=self.params.get("altchars")).decode())
                            else:
                                _cursor.execute("SELECT * FROM users WHERE id=%s LIMIT 0, 1" % self.params["id"])
                        results = _cursor.fetchall()

                    output += "<b>SQL results:</b><br>\n"

                    if self.params.get("code", ""):
                        if not results:
                            code = INTERNAL_SERVER_ERROR
                    else:
                        if results:
                            output += "<table border=\"1\">\n"

                            for row in results:
                                output += "<tr>"
                                for value in row:
                                    output += "<td>%s</td>" % value
                                output += "</tr>\n"

                            output += "</table>\n"
                        else:
                            output += "no results found"

                    output += "</body></html>"
                except Exception as ex:
                    code = INTERNAL_SERVER_ERROR
                    output = "%s: %s" % (re.search(r"'([^']+)'", str(type(ex))).group(1), ex)

                self.send_response(code)

                self.send_header("Content-type", "text/html")
                self.send_header("Connection", "close")

                if self.raw_requestline.startswith(b"HEAD"):
                    self.send_header("Content-Length", str(len(output)))
                    self.end_headers()
                else:
                    self.end_headers()
                    self.wfile.write(output if isinstance(output, bytes) else output.encode(UNICODE_ENCODING))
        else:
            self.send_response(NOT_FOUND)
            self.send_header("Connection", "close")
            self.end_headers()

    def do_GET(self):
        self.do_REQUEST()

    def do_PUT(self):
        self.do_POST()

    def do_HEAD(self):
        self.do_REQUEST()

    def do_POST(self):
        length = int(self.headers.get("Content-length", 0))
        if length:
            data = self.rfile.read(length)
            data = unquote_plus(data.decode(UNICODE_ENCODING, "ignore"))
            self.data = data
        elif self.headers.get("Transfer-encoding") == "chunked":
            data, line = b"", b""
            count = 0

            while True:
                line += self.rfile.read(1)
                if line.endswith(b'\n'):
                    if count % 2 == 1:
                        current = line.rstrip(b"\r\n")
                        if not current:
                            break
                        else:
                            data += current

                    count += 1
                    line = b""

            self.data = data.decode(UNICODE_ENCODING, "ignore")

        self.do_REQUEST()

    def log_message(self, format, *args):
        return

def run(address=LISTEN_ADDRESS, port=LISTEN_PORT):
    global _alive
    global _server
    try:
        _alive = True
        _server = ThreadingServer((address, port), ReqHandler)
        print("[i] running HTTP server at 'http://%s:%d'" % (address, port))
        _server.serve_forever()
    except KeyboardInterrupt:
        _server.socket.close()
        raise
    finally:
        _alive = False

if __name__ == "__main__":
    try:
        init()
        run(sys.argv[1] if len(sys.argv) > 1 else LISTEN_ADDRESS, int(sys.argv[2] if len(sys.argv) > 2 else LISTEN_PORT))
    except KeyboardInterrupt:
        print("\r[x] Ctrl-C received")
