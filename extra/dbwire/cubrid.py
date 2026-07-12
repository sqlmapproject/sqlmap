#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
Minimal pure-python CUBRID client speaking the CAS (Common Application Server) broker protocol (stdlib
only, no CUBRID-Python/CCI). Does the 10-byte broker handshake (+ optional CAS-worker redirect), a
cleartext OPEN_DATABASE login, then prepare / execute / fetch with column-metadata decoding. Read-oriented
for sqlmap: execute() takes a fully-formed query string, binary (BIT/VARBIT/BLOB) values come back as bytes
(sqlmap hex-encodes them). Auto-commit is enabled so each statement is independent.
"""

import datetime
import socket
import struct

from extra.dbwire import DatabaseError
from extra.dbwire import DataError
from extra.dbwire import InterfaceError
from extra.dbwire import IntegrityError
from extra.dbwire import NotSupportedError
from extra.dbwire import OperationalError
from extra.dbwire import ProgrammingError

_MAGIC = b"CUBRK"
_CLIENT_JDBC = 3
_CAS_VERSION = 0x48  # PROTO_INDICATOR(0x40) | VERSION(8)

# function codes (first raw byte of each request)
_FC_END_TRAN = 1
_FC_PREPARE = 2
_FC_EXECUTE = 3
_FC_SET_DB_PARAMETER = 5
_FC_CLOSE_REQ_HANDLE = 6
_FC_FETCH = 8
_FC_CON_CLOSE = 31

_TRAN_COMMIT = 1
_TRAN_ROLLBACK = 2
_PARAM_AUTO_COMMIT = 4

_OID_SIZE = 8
_STMT_SELECT = 21

# CUBRID CCI_U_TYPE column type codes
_T_CHAR = 1
_T_STRING = 2
_T_NCHAR = 3
_T_VARNCHAR = 4
_T_BIT = 5
_T_VARBIT = 6
_T_NUMERIC = 7
_T_INT = 8
_T_SHORT = 9
_T_MONETARY = 10
_T_FLOAT = 11
_T_DOUBLE = 12
_T_DATE = 13
_T_TIME = 14
_T_TIMESTAMP = 15
_T_OBJECT = 19
_T_BIGINT = 21
_T_DATETIME = 22
_T_BLOB = 23
_T_CLOB = 24
_T_ENUM = 25
_T_JSON = 34
_STRING_TYPES = frozenset((_T_CHAR, _T_STRING, _T_NCHAR, _T_VARNCHAR, _T_ENUM, _T_JSON))
_BINARY_TYPES = frozenset((_T_BIT, _T_VARBIT, _T_BLOB, _T_CLOB))

_MAX_MESSAGE_LENGTH = 0x40000000  # guard against a hostile/corrupt length

class _Writer(object):
    # builds a request payload (after the 8-byte header): raw function code + length-prefixed args
    def __init__(self, fc):
        self._buf = bytearray(struct.pack(">B", fc))

    def raw_int(self, v):
        self._buf += struct.pack(">i", v); return self

    def raw_byte(self, v):
        self._buf += struct.pack(">B", v); return self

    def arg_int(self, v):
        self._buf += struct.pack(">ii", 4, v); return self

    def arg_byte(self, v):
        self._buf += struct.pack(">iB", 1, v); return self

    def arg_null(self):
        self._buf += struct.pack(">i", 0); return self

    def arg_cache_time(self):
        self._buf += struct.pack(">iii", 8, 0, 0); return self

    def arg_nts(self, s):  # null-terminated string arg: [len(utf8)+1][utf8][00]
        b = s.encode("utf-8")
        self._buf += struct.pack(">i", len(b) + 1) + b + b"\x00"; return self

    def payload(self):
        return bytes(self._buf)

class _Reader(object):
    def __init__(self, buf):
        self._buf = buf
        self._off = 0

    def remaining(self):
        return len(self._buf) - self._off

    def byte(self):
        v = struct.unpack_from(">B", self._buf, self._off)[0]; self._off += 1; return v

    def short(self):
        v = struct.unpack_from(">h", self._buf, self._off)[0]; self._off += 2; return v

    def int(self):
        v = struct.unpack_from(">i", self._buf, self._off)[0]; self._off += 4; return v

    def long(self):
        v = struct.unpack_from(">q", self._buf, self._off)[0]; self._off += 8; return v

    def float(self):
        v = struct.unpack_from(">f", self._buf, self._off)[0]; self._off += 4; return v

    def double(self):
        v = struct.unpack_from(">d", self._buf, self._off)[0]; self._off += 8; return v

    def raw(self, n):
        v = self._buf[self._off:self._off + n]; self._off += n; return bytes(v)

    def skip(self, n):
        self._off += n

    def nts(self, n):  # n bytes, drop one trailing NUL if present
        b = self.raw(n)
        if b and bytearray(b)[-1:] == bytearray(b"\x00"):
            b = b[:-1]
        return b

def _decode_text(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw  # non-UTF-8 -> keep bytes (sqlmap hex-encodes), not lossy

def _decode_value(reader, col_type, size):
    if col_type in _STRING_TYPES:
        return _decode_text(reader.nts(size))
    if col_type in (_T_BIT, _T_VARBIT):
        return reader.raw(size)
    if col_type == _T_NUMERIC:
        return _decode_text(reader.nts(size))  # DECIMAL arrives as ASCII text
    if col_type == _T_INT:
        return str(reader.int())
    if col_type == _T_SHORT:
        return str(reader.short())
    if col_type == _T_BIGINT:
        return str(reader.long())
    if col_type == _T_FLOAT:
        return repr(reader.float())
    if col_type in (_T_DOUBLE, _T_MONETARY):
        return repr(reader.double())
    if col_type == _T_DATE:
        y, mo, d = reader.short(), reader.short(), reader.short()
        return "%s" % datetime.date(y, mo, d)
    if col_type == _T_TIME:
        h, mi, s = reader.short(), reader.short(), reader.short()
        return "%s" % datetime.time(h, mi, s)
    if col_type == _T_TIMESTAMP:
        vals = [reader.short() for _ in range(6)]
        return "%s" % datetime.datetime(*vals)
    if col_type == _T_DATETIME:
        y, mo, d, h, mi, s, ms = (reader.short() for _ in range(7))
        return "%s" % datetime.datetime(y, mo, d, h, mi, s, ms * 1000)
    if col_type == _T_OBJECT:
        page, slot, vol = reader.int(), reader.short(), reader.short()
        return "OID:@%d|%d|%d" % (page, slot, vol)
    return reader.raw(size)  # BLOB/CLOB locator or unknown type -> raw bytes

class _Column(object):
    __slots__ = ("name", "type", "scale", "precision")

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
    def __init__(self, host, port, user, password, database, timeout):
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._database = database
        self._timeout = timeout
        self._sock = None
        self._cas_info = b"\x00\x00\x00\x00"
        self._protocol_version = 8
        self._open()

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self._call(_Writer(_FC_END_TRAN).arg_byte(_TRAN_COMMIT))

    def rollback(self):
        self._call(_Writer(_FC_END_TRAN).arg_byte(_TRAN_ROLLBACK))

    def close(self):
        try:
            if self._sock is not None:
                self._send(_Writer(_FC_CON_CLOSE).payload())
        except Exception:
            pass
        self._safe_close()

    # ---- connection / framing ----

    def _safe_close(self):
        try:
            if self._sock is not None:
                self._sock.close()
        except Exception:
            pass
        self._sock = None

    def _recvn(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise InterfaceError("connection closed by server")
            buf += chunk
        return buf

    def _open(self):
        # broker handshake (may redirect to a dedicated CAS worker port), then cleartext OPEN_DATABASE login
        try:
            sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
            sock.settimeout(None)
            sock.sendall(_MAGIC + struct.pack(">BB", _CLIENT_JDBC, _CAS_VERSION) + b"\x00\x00\x00")
            self._sock = sock
            (port,) = struct.unpack(">i", self._recvn(4))
            if port < 0:
                raise OperationalError("CUBRID broker rejected the connection (status %d)" % port)
            if port > 0:  # redirected to a CAS worker: reconnect there, no second handshake
                self._safe_close()
                sock = socket.create_connection((self._host, port), timeout=self._timeout)
                sock.settimeout(None)
                self._sock = sock
        except (socket.error, socket.timeout) as ex:
            self._safe_close()
            raise OperationalError("could not connect to '%s:%s' (%s)" % (self._host, self._port, ex))

        login = self._fixed(self._database, 32) + self._fixed(self._user, 32) + self._fixed(self._password, 32)
        login += b"\x00" * 532  # 512 extended-info + 20 reserved
        self._sock.sendall(login)
        reader = self._read_response()
        reader.int()                 # response_code (>=0; errors already raised in _read_response)
        broker = reader.raw(8)
        self._protocol_version = bytearray(broker)[4] & 0x3f
        # enable auto-commit so each statement is independent (avoids the CAS keep-connection handshake dance)
        self._call(_Writer(_FC_SET_DB_PARAMETER).arg_int(_PARAM_AUTO_COMMIT).arg_int(1))

    @staticmethod
    def _fixed(value, length):
        b = (value or "").encode("utf-8")[:length]
        return b + b"\x00" * (length - len(b))

    def _send(self, payload):
        # frame: [payload_len(4)][cas_info(4)][payload]
        self._sock.sendall(struct.pack(">i", len(payload)) + self._cas_info + payload)

    def _read_response(self):
        (data_length,) = struct.unpack(">i", self._recvn(4))
        if data_length < 0 or data_length > _MAX_MESSAGE_LENGTH:
            raise InterfaceError("invalid CAS response length (%d)" % data_length)
        body = self._recvn(data_length + 4)  # cas_info(4) + payload(data_length)
        self._cas_info = body[:4]
        reader = _Reader(body[4:])
        peek = struct.unpack_from(">i", body, 4)[0]
        if peek < 0:  # error response: response_code(<0), errno, message
            reader.int()
            errno = reader.int()
            message = _decode_text(reader.nts(reader.remaining()))
            if not isinstance(message, str):
                message = "errno %d" % errno
            self._raise(errno, "(remote) %s" % message.strip())
        return reader

    def _call(self, writer):
        # reconnect transparently if the CAS worker was released after a previous auto-committed statement
        if self._sock is None or bytearray(self._cas_info)[0] == 0:
            self._open()
        try:
            self._send(writer.payload() if isinstance(writer, _Writer) else writer)
            return self._read_response()
        except (struct.error, IndexError, ValueError) as ex:
            raise InterfaceError("malformed server response: %s" % ex)

    @staticmethod
    def _raise(errno, message):
        text = message.lower()
        if any(k in text for k in ("unique", "duplicate", "foreign key", "constraint violat")):
            raise IntegrityError(message)
        if any(k in text for k in ("syntax", "unknown class", "does not exist", "not found", "before ' '")):
            raise ProgrammingError(message)
        if any(k in text for k in ("cast", "conversion", "overflow", "truncat")):
            raise DataError(message)
        raise ProgrammingError(message)

    # ---- query ----

    def _query(self, query):
        reader = self._call(_Writer(_FC_PREPARE).arg_nts(query).arg_byte(0).arg_byte(0))
        handle = reader.int()
        reader.int()                 # result cache lifetime
        stmt_type = reader.byte()
        reader.int()                 # bind count
        reader.byte()                # is_updatable
        columns = self._parse_columns(reader, reader.int())

        exec_writer = (_Writer(_FC_EXECUTE).arg_int(handle).arg_byte(0).arg_int(0).arg_int(0)
                       .arg_null().arg_byte(1 if stmt_type == _STMT_SELECT else 0)
                       .arg_byte(0).arg_byte(1).arg_cache_time().arg_int(0))
        reader = self._call(exec_writer)

        total = reader.int()
        reader.byte()                # cache reusable
        result_count = reader.int()
        result_infos = [self._parse_result_info(reader) for _ in range(result_count)]
        if self._protocol_version > 1:
            reader.byte()            # includes_column_info
        if self._protocol_version > 4:
            reader.int()             # shard_id

        description, rows, rowcount = None, [], -1
        if stmt_type == _STMT_SELECT and columns:
            description = [(c.name, c.type, None, None, c.precision, c.scale, None) for c in columns]
            if reader.remaining() >= 8:
                reader.int()         # fetch code
                tuple_count = reader.int()
                rows = self._parse_rows(reader, tuple_count, columns)
            rows += self._fetch_remaining(handle, columns, len(rows), total)
        elif result_infos:
            rowcount = result_infos[0]
        self._call(_Writer(_FC_CLOSE_REQ_HANDLE).arg_int(handle))
        return description, rows, rowcount

    def _fetch_remaining(self, handle, columns, fetched, total):
        rows = []
        while fetched + len(rows) < total:
            reader = self._call(_Writer(_FC_FETCH).arg_int(handle)
                                .arg_int(fetched + len(rows) + 1).arg_int(100).arg_byte(0).arg_int(0))
            reader.int()             # response code (>=0)
            tuple_count = reader.int()
            if tuple_count <= 0:
                break
            rows += self._parse_rows(reader, tuple_count, columns)
        return rows

    def _parse_result_info(self, reader):
        reader.byte()                # stmt type
        count = reader.int()         # affected rows
        reader.raw(_OID_SIZE)
        reader.int(); reader.int()   # cache time sec/usec
        return count

    def _parse_columns(self, reader, count):
        columns = []
        for _ in range(count):
            col = _Column()
            legacy = reader.byte()
            col.type = reader.byte() if legacy & 0x80 else legacy
            col.scale = reader.short()
            col.precision = reader.int()
            col.name = _to_str(reader.nts(reader.int()))
            reader.nts(reader.int())          # real name
            reader.nts(reader.int())          # table name
            reader.byte()                     # is_nullable
            reader.nts(reader.int())          # default value
            reader.skip(7)                    # auto_inc/unique/primary/rev_index/rev_unique/foreign/shared
            columns.append(col)
        return columns

    def _parse_rows(self, reader, tuple_count, columns):
        rows = []
        for _ in range(tuple_count):
            reader.int()             # row index
            reader.skip(_OID_SIZE)
            row = []
            for col in columns:
                size = reader.int()
                if size <= 0:
                    row.append(None)
                else:
                    row.append(_decode_value(reader, col.type, size))
            rows.append(tuple(row))
        return rows

def _to_str(b):
    v = _decode_text(b)
    return v if isinstance(v, str) else v.decode("latin-1")

def connect(host=None, port=33000, user=None, password=None, database=None, connect_timeout=None, **kwargs):
    try:
        return Connection(host or "localhost", int(port or 33000), user or "public",
                          password or "", database or "", connect_timeout)
    except (DatabaseError, InterfaceError):
        raise
    except Exception as ex:
        raise OperationalError("CUBRID connection failed (%s)" % ex)
