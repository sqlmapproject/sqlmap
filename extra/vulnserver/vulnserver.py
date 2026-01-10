#!/usr/bin/env python

"""
vulnserver.py - Trivial SQLi vulnerable HTTP server (Note: for testing purposes)

Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import base64
import json
import random
import re
import sqlite3
import string
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
    INSERT INTO users (id, name, surname) VALUES (3, 'wu', 'ming');
    INSERT INTO users (id, name, surname) VALUES (4, NULL, 'nameisnull');
    INSERT INTO users (id, name, surname) VALUES (5, 'mark', 'lewis');
    INSERT INTO users (id, name, surname) VALUES (6, 'ada', 'lovelace');
    INSERT INTO users (id, name, surname) VALUES (7, 'grace', 'hopper');
    INSERT INTO users (id, name, surname) VALUES (8, 'alan', 'turing');
    INSERT INTO users (id, name, surname) VALUES (9, 'margaret','hamilton');
    INSERT INTO users (id, name, surname) VALUES (10, 'donald', 'knuth');
    INSERT INTO users (id, name, surname) VALUES (11, 'tim', 'bernerslee');
    INSERT INTO users (id, name, surname) VALUES (12, 'linus', 'torvalds');
    INSERT INTO users (id, name, surname) VALUES (13, 'ken', 'thompson');
    INSERT INTO users (id, name, surname) VALUES (14, 'dennis', 'ritchie');
    INSERT INTO users (id, name, surname) VALUES (15, 'barbara', 'liskov');
    INSERT INTO users (id, name, surname) VALUES (16, 'edsger', 'dijkstra');
    INSERT INTO users (id, name, surname) VALUES (17, 'john', 'mccarthy');
    INSERT INTO users (id, name, surname) VALUES (18, 'leslie', 'lamport');
    INSERT INTO users (id, name, surname) VALUES (19, 'niklaus', 'wirth');
    INSERT INTO users (id, name, surname) VALUES (20, 'bjarne', 'stroustrup');
    INSERT INTO users (id, name, surname) VALUES (21, 'guido', 'vanrossum');
    INSERT INTO users (id, name, surname) VALUES (22, 'brendan', 'eich');
    INSERT INTO users (id, name, surname) VALUES (23, 'james', 'gosling');
    INSERT INTO users (id, name, surname) VALUES (24, 'andrew', 'tanenbaum');
    INSERT INTO users (id, name, surname) VALUES (25, 'yukihiro','matsumoto');
    INSERT INTO users (id, name, surname) VALUES (26, 'radia', 'perlman');
    INSERT INTO users (id, name, surname) VALUES (27, 'katherine','johnson');
    INSERT INTO users (id, name, surname) VALUES (28, 'hady', 'lamarr');
    INSERT INTO users (id, name, surname) VALUES (29, 'frank', 'miller');
    INSERT INTO users (id, name, surname) VALUES (30, 'john', 'steward');

    CREATE TABLE creds (
        user_id INTEGER,
        password_hash TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    INSERT INTO creds (user_id, password_hash) VALUES (1, 'db3a16990a0008a3b04707fdef6584a0');
    INSERT INTO creds (user_id, password_hash) VALUES (2, '4db967ce67b15e7fb84c266a76684729');
    INSERT INTO creds (user_id, password_hash) VALUES (3, 'f5a2950eaa10f9e99896800eacbe8275');
    INSERT INTO creds (user_id, password_hash) VALUES (4, NULL);
    INSERT INTO creds (user_id, password_hash) VALUES (5, '179ad45c6ce2cb97cf1029e212046e81');
    INSERT INTO creds (user_id, password_hash) VALUES (6, '0f1e2d3c4b5a69788796a5b4c3d2e1f0');
    INSERT INTO creds (user_id, password_hash) VALUES (7, 'a1b2c3d4e5f60718293a4b5c6d7e8f90');
    INSERT INTO creds (user_id, password_hash) VALUES (8, '1a2b3c4d5e6f708192a3b4c5d6e7f809');
    INSERT INTO creds (user_id, password_hash) VALUES (9, '9f8e7d6c5b4a3928170605f4e3d2c1b0');
    INSERT INTO creds (user_id, password_hash) VALUES (10, '3c2d1e0f9a8b7c6d5e4f30291807f6e5');
    INSERT INTO creds (user_id, password_hash) VALUES (11, 'b0c1d2e3f405162738495a6b7c8d9eaf');
    INSERT INTO creds (user_id, password_hash) VALUES (12, '6e5d4c3b2a190807f6e5d4c3b2a1908f');
    INSERT INTO creds (user_id, password_hash) VALUES (13, '11223344556677889900aabbccddeeff');
    INSERT INTO creds (user_id, password_hash) VALUES (14, 'ffeeddccbbaa00998877665544332211');
    INSERT INTO creds (user_id, password_hash) VALUES (15, '1234567890abcdef1234567890abcdef');
    INSERT INTO creds (user_id, password_hash) VALUES (16, 'abcdef1234567890abcdef1234567890');
    INSERT INTO creds (user_id, password_hash) VALUES (17, '0a1b2c3d4e5f60718a9b0c1d2e3f4051');
    INSERT INTO creds (user_id, password_hash) VALUES (18, '51f04e3d2c1b0a9871605f4e3d2c1b0a');
    INSERT INTO creds (user_id, password_hash) VALUES (19, '89abcdef0123456789abcdef01234567');
    INSERT INTO creds (user_id, password_hash) VALUES (20, '76543210fedcba9876543210fedcba98');
    INSERT INTO creds (user_id, password_hash) VALUES (21, '13579bdf2468ace013579bdf2468ace0');
    INSERT INTO creds (user_id, password_hash) VALUES (22, '02468ace13579bdf02468ace13579bdf');
    INSERT INTO creds (user_id, password_hash) VALUES (23, 'deadbeefdeadbeefdeadbeefdeadbeef');
    INSERT INTO creds (user_id, password_hash) VALUES (24, 'cafebabecafebabecafebabecafebabe');
    INSERT INTO creds (user_id, password_hash) VALUES (25, '00112233445566778899aabbccddeeff');
    INSERT INTO creds (user_id, password_hash) VALUES (26, 'f0e1d2c3b4a5968778695a4b3c2d1e0f');
    INSERT INTO creds (user_id, password_hash) VALUES (27, '7f6e5d4c3b2a190807f6e5d4c3b2a190');
    INSERT INTO creds (user_id, password_hash) VALUES (28, '908f7e6d5c4b3a291807f6e5d4c3b2a1');
    INSERT INTO creds (user_id, password_hash) VALUES (29, '3049b791fa83e2f42f37bae18634b92d');
    INSERT INTO creds (user_id, password_hash) VALUES (30, 'd59a348f90d757c7da30418773424b5e');
"""

LISTEN_ADDRESS = "localhost"
LISTEN_PORT = 8440

_conn = None
_cursor = None
_lock = None
_server = None
_alive = False
_csrf_token = None

def init(quiet=False):
    global _conn
    global _cursor
    global _lock
    global _csrf_token

    _csrf_token = "".join(random.sample(string.ascii_letters + string.digits, 20))

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

        if self.url == "/csrf":
            if self.params.get("csrf_token") == _csrf_token:
                self.url = "/"
            else:
                self.send_response(OK)
                self.send_header("Content-type", "text/html; charset=%s" % UNICODE_ENCODING)
                self.end_headers()

                form = (
                    "<html><body>"
                    "CSRF protection check<br>"
                    "<form action='/csrf' method='POST'>"
                    "<input type='hidden' name='csrf_token' value='%s'>"
                    "id: <input type='text' name='id'>"
                    "<input type='submit' value='Submit'>"
                    "</form>"
                    "</body></html>"
                ) % _csrf_token

                self.wfile.write(form.encode(UNICODE_ENCODING))
                return

        if self.url == '/':
            if not any(_ in self.params for _ in ("id", "query")):
                self.send_response(OK)
                self.send_header("Content-type", "text/html; charset=%s" % UNICODE_ENCODING)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"<!DOCTYPE html><html><head><title>vulnserver</title></head><body><h3>GET:</h3><a href='/?id=1'>link</a><hr><h3>POST:</h3><form method='post'>ID: <input type='text' name='id'><input type='submit' value='Submit'></form></body></html>")
            else:
                code, output = OK, "<body><html>"

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

                        if not results:
                            output = "<title>No results</title>" + output
                        else:
                            output = "<title>Results</title>" + output

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
