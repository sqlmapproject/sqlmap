#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
Minimal pure-python PostgreSQL frontend/backend protocol v3 client (stdlib only).

Covers the whole PostgreSQL-wire family (PostgreSQL, CockroachDB, CrateDB, Redshift, Greenplum, ...).
Auth: trust / cleartext / MD5 / SCRAM-SHA-256 (modern default). Uses the *simple query* protocol, whose
per-message implicit transaction auto-commits - so it is immune to the aborted-transaction poisoning and
commit-before-fetch pitfalls that bite the stateful native drivers. Binary (bytea) values arrive as the
server's readable '\\xHEX' text (text result format), so no memoryview/blob corruption either.
"""

import base64
import binascii
import hashlib
import hmac
import os
import socket
import struct

from extra.dbwire import DatabaseError
from extra.dbwire import DataError
from extra.dbwire import IntegrityError
from extra.dbwire import InterfaceError
from extra.dbwire import NotSupportedError
from extra.dbwire import OperationalError
from extra.dbwire import ProgrammingError

_PROTOCOL_VERSION = 196608  # 3.0
_MAX_MESSAGE_LENGTH = 0x40000000  # 1 GB - guard against a hostile/corrupt length triggering an unbounded read

# SQLSTATE class (first 2 chars) -> DB-API exception, so callers can distinguish (mirrors psycopg2)
_SQLSTATE_CLASS = {
    "22": DataError, "23": IntegrityError,
    "08": OperationalError, "28": OperationalError, "53": OperationalError,
    "57": OperationalError, "58": OperationalError,
}

def _xor(a, b):
    # byte-wise XOR of two equal-length byte strings (Python 2 and 3 safe)
    if str is bytes:  # Python 2: iterating bytes yields 1-char strings
        return b"".join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))
    return bytes(x ^ y for x, y in zip(a, b))

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise InterfaceError("connection closed by server")
        buf += chunk
    return buf

def _read_message(sock):
    mtype = _recvn(sock, 1)
    (length,) = struct.unpack("!I", _recvn(sock, 4))
    if length < 4 or length > _MAX_MESSAGE_LENGTH:
        raise InterfaceError("invalid backend message length (%d)" % length)
    return mtype, _recvn(sock, length - 4)

def _send(sock, mtype, payload):
    sock.sendall((mtype or b"") + struct.pack("!I", len(payload) + 4) + payload)

def _error_message(payload):
    # ErrorResponse/NoticeResponse: series of (byte field-code, cstring value), terminated by a NUL byte.
    # Returns (human message, SQLSTATE). Tolerant of a truncated/unterminated stream (find() not index()).
    fields, off = {}, 0
    while off < len(payload) and payload[off:off + 1] != b"\x00":
        code = payload[off:off + 1]
        end = payload.find(b"\x00", off + 1)
        if end == -1:
            break
        fields[code] = payload[off + 1:end].decode("utf-8", "replace")
        off = end + 1
    return fields.get(b"M", "unknown error"), fields.get(b"C", "")

def _raise_server_error(message, sqlstate):
    raise _SQLSTATE_CLASS.get((sqlstate or "")[:2], ProgrammingError)("(remote) %s" % message)

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
        self.description, self.rowcount, self._rows, self._pos = None, -1, [], 0  # reset before (a failed) query
        self.description, self._rows, self._pos, self.rowcount = self.connection._simple_query(query)
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
        pass  # simple-query protocol commits each statement implicitly

    def rollback(self):
        pass

    def close(self):
        try:
            _send(self._sock, b"X", b"")  # Terminate
        except Exception:
            pass
        try:
            self._sock.close()
        except Exception:
            pass

    def _simple_query(self, query):
        _send(self._sock, b"Q", query.encode("utf-8") + b"\x00")

        description, rows, rowcount, error = None, [], -1, None
        while True:
            mtype, payload = _read_message(self._sock)
            try:
                if mtype == b"T":  # RowDescription (a new result set: reset rows so we return only the last one)
                    (count,) = struct.unpack("!H", payload[:2])
                    description, rows, rowcount, off = [], [], -1, 2
                    for _ in range(count):
                        end = payload.index(b"\x00", off)
                        name = payload[off:end].decode("utf-8", "replace")
                        off = end + 1
                        (typeoid,) = struct.unpack("!I", payload[off + 6:off + 10])
                        off += 18  # tableoid4 colno2 typeoid4 typelen2 typmod4 format2
                        description.append((name, typeoid, None, None, None, None, None))
                elif mtype == b"D":  # DataRow
                    (count,) = struct.unpack("!H", payload[:2])
                    off, row = 2, []
                    for _ in range(count):
                        (vlen,) = struct.unpack("!i", payload[off:off + 4])
                        off += 4
                        if vlen == -1:
                            row.append(None)
                        else:
                            if off + vlen > len(payload):
                                raise InterfaceError("truncated DataRow")
                            row.append(payload[off:off + vlen].decode("utf-8", "replace"))
                            off += vlen
                    rows.append(tuple(row))
                elif mtype == b"C":  # CommandComplete ("SELECT 3", "INSERT 0 1", ...)
                    tag = payload[:-1].decode("utf-8", "replace").split()
                    if tag and tag[-1].isdigit():
                        rowcount = int(tag[-1])
                elif mtype == b"G":  # CopyInResponse - server now waits for client CopyData; refuse to avoid a deadlock
                    _send(self._sock, b"f", b"COPY FROM STDIN is not supported\x00")  # CopyFail
                elif mtype == b"E":  # ErrorResponse
                    error = _error_message(payload)
                elif mtype == b"Z":  # ReadyForQuery (end of response)
                    break
                # ParameterStatus(S)/NoticeResponse(N)/EmptyQueryResponse(I)/CopyData(d)/CopyDone(c)/... ignored
            except (struct.error, IndexError, ValueError) as ex:
                raise InterfaceError("malformed backend message: %s" % ex)
        if error is not None:
            _raise_server_error(*error)
        return description, rows, 0, rowcount

def _authenticate(sock, user, password):
    cfirst_bare = None
    while True:
        mtype, payload = _read_message(sock)
        if mtype in (b"N", b"S"):  # NoticeResponse / ParameterStatus may legally precede AuthenticationOk
            continue
        if mtype == b"E":
            _raise_server_error_as_operational(payload)
        if mtype != b"R":
            raise InterfaceError("unexpected message %r during authentication" % mtype)
        (code,) = struct.unpack("!I", payload[:4])
        if code == 0:  # AuthenticationOk (also the trust case)
            return
        elif code == 3:  # cleartext password
            _send(sock, b"p", (password or "").encode("utf-8") + b"\x00")
        elif code == 5:  # MD5 password
            salt = payload[4:8]
            inner = hashlib.md5((password or "").encode("utf-8") + (user or "").encode("utf-8")).hexdigest()
            token = b"md5" + hashlib.md5(inner.encode("ascii") + salt).hexdigest().encode("ascii")
            _send(sock, b"p", token + b"\x00")
        elif code == 10:  # SASL (SCRAM-SHA-256)
            if not hasattr(hashlib, "pbkdf2_hmac"):
                raise NotSupportedError("SCRAM-SHA-256 authentication requires Python >= 2.7.8 (hashlib.pbkdf2_hmac)")
            nonce = base64.b64encode(os.urandom(18)).decode("ascii")
            cfirst_bare = "n=,r=%s" % nonce
            client_first = "n,," + cfirst_bare
            _send(sock, b"p", b"SCRAM-SHA-256\x00" + struct.pack("!I", len(client_first)) + client_first.encode("ascii"))
        elif code == 11:  # SASLContinue (server-first)
            try:
                server_first = payload[4:].decode("ascii")
                attrs = dict(kv.split("=", 1) for kv in server_first.split(","))
                snonce, salt, iterations = attrs["r"], base64.b64decode(attrs["s"]), int(attrs["i"])
            except (KeyError, ValueError, binascii.Error, UnicodeDecodeError) as ex:
                raise OperationalError("malformed SCRAM server-first message (%s)" % ex)
            salted = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, iterations)
            client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
            stored_key = hashlib.sha256(client_key).digest()
            client_final_noproof = "c=biws,r=%s" % snonce
            auth_message = "%s,%s,%s" % (cfirst_bare, server_first, client_final_noproof)
            client_sig = hmac.new(stored_key, auth_message.encode("ascii"), hashlib.sha256).digest()
            proof = base64.b64encode(_xor(client_key, client_sig)).decode("ascii")
            _send(sock, b"p", ("%s,p=%s" % (client_final_noproof, proof)).encode("ascii"))
        elif code == 12:  # SASLFinal
            pass
        else:
            raise InterfaceError("unsupported authentication request %d" % code)

def _raise_server_error_as_operational(payload):
    message, _ = _error_message(payload)
    raise OperationalError("(remote) %s" % message)

def connect(host=None, port=5432, user=None, password=None, database=None, connect_timeout=None, **kwargs):
    try:
        sock = socket.create_connection((host or "localhost", int(port or 5432)), timeout=connect_timeout)
        sock.settimeout(None)
    except (socket.error, socket.timeout) as ex:
        raise OperationalError("could not connect to '%s:%s' (%s)" % (host, port, ex))

    params = b""
    for key, value in (("user", user or ""), ("database", database or user or ""), ("client_encoding", "UTF8")):
        params += key.encode("ascii") + b"\x00" + ("%s" % value).encode("utf-8") + b"\x00"
    params += b"\x00"
    _send(sock, b"", struct.pack("!I", _PROTOCOL_VERSION) + params)

    try:
        _authenticate(sock, user, password)
        while True:  # drain until ReadyForQuery (ParameterStatus/BackendKeyData/NoticeResponse)
            mtype, payload = _read_message(sock)
            if mtype == b"E":
                _raise_server_error_as_operational(payload)
            if mtype == b"Z":
                break
    except Exception:  # any setup failure (DB-API or otherwise) must still close the socket
        try:
            sock.close()
        except Exception:
            pass
        raise

    return Connection(sock)
