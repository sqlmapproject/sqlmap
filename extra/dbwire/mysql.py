#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
Minimal pure-python MySQL client/server protocol client (stdlib only).

Covers the whole MySQL-wire family (MySQL, MariaDB, TiDB, Aurora-MySQL, Percona, ...). Auth:
mysql_native_password (full), plus caching_sha2_password fast path; caching_sha2 *full* auth over a
plaintext connection needs RSA (not in the stdlib), so that case raises a clean NotSupportedError - use a
mysql_native_password account (as MariaDB/TiDB default to) for the dependency-free path.
"""

import hashlib
import socket
import struct

from extra.dbwire import DatabaseError
from extra.dbwire import InterfaceError
from extra.dbwire import NotSupportedError
from extra.dbwire import OperationalError
from extra.dbwire import ProgrammingError

# capability flags
_CLIENT_LONG_PASSWORD = 0x00000001
_CLIENT_LONG_FLAG = 0x00000004
_CLIENT_CONNECT_WITH_DB = 0x00000008
_CLIENT_PROTOCOL_41 = 0x00000200
_CLIENT_TRANSACTIONS = 0x00002000
_CLIENT_SECURE_CONNECTION = 0x00008000
_CLIENT_PLUGIN_AUTH = 0x00080000

_MAX_PACKET = 0x1000000
_MAX_MESSAGE_LENGTH = 0x40000000  # cap on a (re-assembled) payload, to bound a hostile/corrupt stream
_BINARY_CHARSET = 63              # collation id 63 == 'binary' (BLOB/BINARY/VARBINARY columns)

def _xor(a, b):
    if str is bytes:  # Python 2
        return b"".join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))
    return bytes(x ^ y for x, y in zip(a, b))

def _u8(data, off):
    return struct.unpack("<B", data[off:off + 1])[0]

def _cstring(data, off):
    # NUL-terminated string, tolerant of a missing terminator (returns the remainder)
    end = data.find(b"\x00", off)
    if end == -1:
        return data[off:], len(data)
    return data[off:end], end + 1

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise InterfaceError("connection closed by server")
        buf += chunk
    return buf

def _read_packet(sock):
    header = _recvn(sock, 4)
    length = struct.unpack("<I", header[0:3] + b"\x00")[0]
    seq = _u8(header, 3)
    payload = _recvn(sock, length)
    total = length
    while length == 0xffffff:  # payload continues in the next packet
        header = _recvn(sock, 4)
        length = struct.unpack("<I", header[0:3] + b"\x00")[0]
        total += length
        if total > _MAX_MESSAGE_LENGTH:
            raise InterfaceError("backend message too large (%d bytes)" % total)
        payload += _recvn(sock, length)
    return seq, payload

def _send_packet(sock, seq, payload):
    while True:  # split payloads >= 16 MB into 0xffffff-sized packets (with a trailing short packet)
        chunk = payload[:0xffffff]
        sock.sendall(struct.pack("<I", len(chunk))[0:3] + struct.pack("<B", seq & 0xff) + chunk)
        seq = (seq + 1) & 0xff
        payload = payload[0xffffff:]
        if len(chunk) < 0xffffff:
            break

def _lenc_int(data, off):
    first = _u8(data, off)
    if first < 0xfb:
        return first, off + 1
    elif first == 0xfb:
        return None, off + 1  # NULL (in a row)
    elif first == 0xfc:
        return struct.unpack("<H", data[off + 1:off + 3])[0], off + 3
    elif first == 0xfd:
        return struct.unpack("<I", data[off + 1:off + 4] + b"\x00")[0], off + 4
    else:  # 0xfe
        return struct.unpack("<Q", data[off + 1:off + 9])[0], off + 9

def _lenc_str(data, off):
    length, off = _lenc_int(data, off)
    if length is None:
        return None, off
    if off + length > len(data):
        raise InterfaceError("length-encoded string overruns packet")
    return data[off:off + length], off + length

def _err_message(payload):
    # ERR packet: 0xff, Int2 code, (if PROTOCOL_41) '#' + 5-byte SQLSTATE, then message
    off = 3
    if payload[3:4] == b"#":
        off = 9
    return payload[off:].decode("utf-8", "replace")

def _scramble_native(password, salt):
    if not password:
        return b""
    stage1 = hashlib.sha1(password.encode("utf-8")).digest()
    stage2 = hashlib.sha1(stage1).digest()
    return _xor(stage1, hashlib.sha1(salt + stage2).digest())

def _scramble_sha2(password, salt):
    if not password:
        return b""
    d1 = hashlib.sha256(password.encode("utf-8")).digest()
    d2 = hashlib.sha256(hashlib.sha256(d1).digest() + salt).digest()
    return _xor(d1, d2)

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
        self.description, self._rows, self.rowcount = self.connection._query(query)
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
        pass  # autocommit is enabled right after connect(), matching sqlmap's autonomous-statement model

    def rollback(self):
        pass

    def close(self):
        try:
            _send_packet(self._sock, 0, b"\x01")  # COM_QUIT
        except Exception:
            pass
        try:
            self._sock.close()
        except Exception:
            pass

    def _query(self, query):
        _send_packet(self._sock, 0, b"\x03" + query.encode("utf-8"))  # COM_QUERY
        try:
            return self._read_query_response()
        except (struct.error, IndexError, ValueError) as ex:
            raise InterfaceError("malformed server response: %s" % ex)

    def _read_query_response(self):
        seq, payload = _read_packet(self._sock)
        first = _u8(payload, 0)

        if first == 0xff:  # ERR
            raise ProgrammingError("(remote) %s" % _err_message(payload))
        if first == 0x00 or (first == 0xfe and len(payload) < 9):  # OK packet (no result set)
            affected, _ = _lenc_int(payload, 1)
            return None, [], (affected if affected is not None else -1)
        if first == 0xfb:  # LOCAL INFILE request
            raise NotSupportedError("LOCAL INFILE is not supported")

        column_count, _ = _lenc_int(payload, 0)
        description, binary = [], []
        for _ in range(column_count):
            _, cpay = _read_packet(self._sock)
            off = 0
            for _ in range(4):  # catalog, schema, table, org_table
                _, off = _lenc_str(cpay, off)
            name, off = _lenc_str(cpay, off)          # name
            _, off = _lenc_str(cpay, off)             # org_name
            _, off = _lenc_int(cpay, off)             # length of the fixed-length block (0x0c)
            charset = struct.unpack("<H", cpay[off:off + 2])[0]
            description.append((name.decode("utf-8", "replace"), None, None, None, None, None, None))
            binary.append(charset == _BINARY_CHARSET)

        _read_packet(self._sock)  # EOF after the column definitions

        rows = []
        while True:
            _, payload = _read_packet(self._sock)
            if _u8(payload, 0) == 0xfe and len(payload) < 9:  # EOF -> end of rows
                break
            if _u8(payload, 0) == 0xff:
                raise ProgrammingError("(remote) %s" % _err_message(payload))
            off, row = 0, []
            for i in range(column_count):
                value, off = _lenc_str(payload, off)
                if value is None:
                    row.append(None)
                elif binary[i]:
                    row.append(value)  # keep binary/BLOB columns as raw bytes (sqlmap hex-encodes them)
                else:
                    row.append(value.decode("utf-8", "replace"))
            rows.append(tuple(row))
        return description, rows, len(rows)

def _finish_auth(sock, password, plugin, salt):
    # read the auth result, handling AuthSwitchRequest (0xfe) and AuthMoreData (0x01) for caching_sha2
    while True:
        seq, payload = _read_packet(sock)
        marker = _u8(payload, 0)
        if marker == 0x00:  # OK
            return
        if marker == 0xff:  # ERR
            raise OperationalError("(remote) %s" % _err_message(payload))
        if marker == 0xfe:  # AuthSwitchRequest: <plugin name>\x00<salt>
            plugin, off = _cstring(payload, 1)
            plugin = plugin.decode("ascii", "replace")
            salt = payload[off:].rstrip(b"\x00")
            if plugin == "mysql_native_password":
                data = _scramble_native(password, salt)
            elif plugin == "caching_sha2_password":
                data = _scramble_sha2(password, salt)
            else:
                raise NotSupportedError("unsupported authentication plugin '%s'" % plugin)
            _send_packet(sock, seq + 1, data)
        elif marker == 0x01:  # AuthMoreData (caching_sha2)
            status = _u8(payload, 1)
            if status == 0x03:  # fast auth success -> OK packet follows
                continue
            elif status == 0x04:  # full auth required (needs TLS or RSA - not available stdlib-only)
                raise NotSupportedError("caching_sha2_password full authentication over a plaintext connection "
                                        "requires RSA/TLS; use a mysql_native_password account for the dependency-free client")
            else:
                raise OperationalError("unexpected caching_sha2 auth status %d" % status)
        else:
            raise InterfaceError("unexpected authentication response 0x%02x" % marker)

def connect(host=None, port=3306, user=None, password=None, database=None, connect_timeout=None, **kwargs):
    try:
        sock = socket.create_connection((host or "localhost", int(port or 3306)), timeout=connect_timeout)
        sock.settimeout(None)
    except (socket.error, socket.timeout) as ex:
        raise OperationalError("could not connect to '%s:%s' (%s)" % (host, port, ex))

    try:
        seq, payload = _read_packet(sock)
        if _u8(payload, 0) == 0xff:
            raise OperationalError("(remote) %s" % _err_message(payload))

        off = 1                                         # protocol version (10)
        _, off = _cstring(payload, off)                 # server version
        off += 4                                        # connection id
        salt = payload[off:off + 8]; off += 8 + 1       # auth-plugin-data part 1 (+ filler)
        off += 2                                        # capability flags (lower)
        off += 1                                        # character set
        off += 2                                        # status flags
        off += 2                                        # capability flags (upper)
        auth_data_len = _u8(payload, off); off += 1
        off += 10                                       # reserved
        salt += payload[off:off + max(13, auth_data_len - 8) - 1]  # part 2 (drop trailing NUL)
        off += max(13, auth_data_len - 8)
        plugin = "mysql_native_password"
        if off < len(payload):
            name, _ = _cstring(payload, off)
            plugin = name.decode("ascii", "replace") or plugin

        if plugin == "caching_sha2_password":
            auth_response = _scramble_sha2(password or "", salt)
        else:
            plugin = "mysql_native_password"
            auth_response = _scramble_native(password or "", salt)

        flags = (_CLIENT_LONG_PASSWORD | _CLIENT_LONG_FLAG | _CLIENT_PROTOCOL_41 |
                 _CLIENT_TRANSACTIONS | _CLIENT_SECURE_CONNECTION | _CLIENT_PLUGIN_AUTH)
        if database:
            flags |= _CLIENT_CONNECT_WITH_DB
        response = struct.pack("<I", flags) + struct.pack("<I", _MAX_PACKET) + struct.pack("<B", 45) + (b"\x00" * 23)
        response += (user or "").encode("utf-8") + b"\x00"
        response += struct.pack("<B", len(auth_response)) + auth_response
        if database:
            response += database.encode("utf-8") + b"\x00"
        response += plugin.encode("ascii") + b"\x00"
        _send_packet(sock, seq + 1, response)

        _finish_auth(sock, password or "", plugin, salt)
    except (DatabaseError, InterfaceError):
        _safe_close(sock)
        raise
    except Exception as ex:
        _safe_close(sock)
        raise OperationalError("handshake failed (%s)" % ex)

    connection = Connection(sock)
    try:
        connection._query("SET autocommit=1")  # so DML persists even if the server default is autocommit=0
    except Exception:
        pass
    return connection

def _safe_close(sock):
    try:
        sock.close()
    except Exception:
        pass
