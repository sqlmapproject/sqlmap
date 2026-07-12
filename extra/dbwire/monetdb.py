#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
Minimal pure-python MonetDB MAPI client (stdlib only, no pymonetdb).

MAPI is a block-framed text protocol: a 2-byte little-endian header (length << 1 | last-flag) wraps each
block; login is a colon-separated challenge/response with a chosen password hash; queries are sent with an
's' prefix and results come back as '&' headers, '%' metadata and '[' tuples. Paging is disabled up front
(Xreply_size -1) so a whole result set arrives at once.
"""

import hashlib
import re
import socket
import struct

from extra.dbwire import InterfaceError
from extra.dbwire import NotSupportedError
from extra.dbwire import OperationalError
from extra.dbwire import ProgrammingError

_MAX_BLOCK = 0xffff >> 1

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise InterfaceError("connection closed by server")
        buf += chunk
    return buf

def _getblock(sock):
    out = b""
    while True:
        (header,) = struct.unpack("<H", _recvn(sock, 2))
        length, last = header >> 1, header & 1
        out += _recvn(sock, length)
        if last:
            break
    return out.decode("utf-8", "replace")

def _putblock(sock, text):
    data = text.encode("utf-8")
    off = 0
    while True:
        chunk = data[off:off + _MAX_BLOCK]
        off += _MAX_BLOCK
        last = off >= len(data)
        sock.sendall(struct.pack("<H", (len(chunk) << 1) | (1 if last else 0)) + chunk)
        if last:
            break

def _challenge_response(challenge, user, password, database):
    parts = challenge.split(":")
    if len(parts) < 7 or parts[-1] != "":
        raise OperationalError("invalid MonetDB challenge")
    salt, server_type, protocol, hashes = parts[0], parts[1], parts[2], parts[3]
    if protocol != "9":
        raise NotSupportedError("only MAPI protocol v9 is supported")
    if server_type == "merovingian":  # proxy stage: authenticate as merovingian, real creds go to the mserver
        user, password = "merovingian", ""
    pwalgo = parts[5]
    try:
        password = hashlib.new(pwalgo, password.encode("utf-8")).hexdigest()
    except ValueError:
        raise NotSupportedError("unsupported MonetDB password algorithm: %s" % pwalgo)
    pwhash = None
    for algo in hashes.split(","):
        try:
            h = hashlib.new(algo)
        except ValueError:
            continue
        h.update(password.encode("utf-8"))
        h.update(salt.encode("utf-8"))
        pwhash = "{%s}%s" % (algo, h.hexdigest())
        break
    if pwhash is None:
        raise NotSupportedError("no supported MonetDB password hash in: %s" % hashes)
    return ":".join(["BIG", user, pwhash, "sql", database or ""]) + ":"

def _unquote(value):
    if value == "NULL":
        return None
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        body = value[1:-1]
        if "\\" not in body:
            return body
        # MonetDB renders control bytes as C octal escapes (\ooo) etc.; decode with unicode_escape but only
        # on the ASCII runs so raw multibyte (> 0x7f) is preserved (mirrors pymonetdb's result decoding)
        return "".join(seg.encode("utf-8").decode("unicode_escape") if "\\" in seg else seg
                       for seg in re.split(r"([\x00-\x7f]+)", body))
    return value

def _parse_result(text):
    description, rows = None, []
    for line in text.split("\n"):
        if not line:
            continue
        marker = line[0]
        if marker == "!":  # error
            raise ProgrammingError("(remote) %s" % line[1:].strip())
        elif marker == "%":  # metadata: "<values> # <kind>"
            payload, _, kind = line[1:].rpartition("#")
            if kind.strip() == "name":
                description = [(name.strip(), None, None, None, None, None, None) for name in payload.split(",\t")]
        elif marker == "[":  # tuple: "[ v1,\tv2,\t... ]"
            body = line.strip()
            if body.startswith("[") and body.endswith("]"):
                body = body[1:-1].strip()
            rows.append(tuple(_unquote(v.strip()) for v in body.split(",\t")))
        # "&" result headers, "#" info, "=" no-slice tuples are ignored for our purposes
    return description, rows

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
    def __init__(self, sock):
        self._sock = sock

    def cursor(self):
        return Cursor(self)

    def commit(self):
        pass  # sqlmap runs autonomous statements; MonetDB SQL is auto-committed unless a transaction is opened

    def rollback(self):
        pass

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass

    def _command(self, text):
        _putblock(self._sock, text)
        reply = _getblock(self._sock)
        if reply.startswith("!"):
            raise OperationalError("(remote) %s" % reply[1:].strip())

    def _query(self, query):
        try:
            _putblock(self._sock, "s" + query + ";\n")
            return _parse_result(_getblock(self._sock))
        except (socket.error, socket.timeout) as ex:
            raise OperationalError("connection error: %s" % ex)
        except (struct.error, IndexError, ValueError) as ex:
            raise InterfaceError("malformed server response: %s" % ex)

def connect(host=None, port=50000, user=None, password=None, database=None, connect_timeout=None, **kwargs):
    host, port = host or "localhost", int(port or 50000)
    try:
        sock = socket.create_connection((host, port), timeout=connect_timeout)
        sock.settimeout(None)
    except (socket.error, socket.timeout) as ex:
        raise OperationalError("could not connect to '%s:%s' (%s)" % (host, port, ex))

    try:
        for _ in range(10):  # bounded: merovingian proxy stage + optional redirect + mserver challenge
            block = _getblock(sock)
            if block == "":  # login accepted
                break
            if block[0] == "^":  # redirect
                url = block[1:].strip()
                m = re.match(r"mapi:monetdb://([^:/]+):(\d+)/(\S*)", url)
                if m and (m.group(1) != host or int(m.group(2)) != port):
                    sock.close()
                    host, port, database = m.group(1), int(m.group(2)), m.group(3) or database
                    sock = socket.create_connection((host, port), timeout=connect_timeout)
                    sock.settimeout(None)
                continue  # merovingian proxy redirect: keep reading the next challenge on this socket
            if block[0] == "!":
                raise OperationalError("(remote) %s" % block[1:].strip())
            _putblock(sock, _challenge_response(block, user, password, database))
        else:
            raise OperationalError("MonetDB login did not converge")
    except (OperationalError, NotSupportedError, InterfaceError):
        try:
            sock.close()
        except Exception:
            pass
        raise
    except (socket.error, socket.timeout) as ex:  # I/O error during the login/redirect exchange
        try:
            sock.close()
        except Exception:
            pass
        raise OperationalError("connection error: %s" % ex)

    connection = Connection(sock)
    try:
        connection._command("Xreply_size -1\n")  # disable row paging so a whole result set is returned at once
    except (socket.error, socket.timeout) as ex:
        connection.close()
        raise OperationalError("connection error: %s" % ex)
    return connection
