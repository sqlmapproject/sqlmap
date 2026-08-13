#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
Minimal pure-python Sybase ASE client speaking TDS 5.0 (stdlib only, no pymssql/FreeTDS).

Sybase and Microsoft share the 8-byte TDS packet framing (reused from tds.py) and part company at the
login: ASE speaks TDS 5.0, which means a fixed-layout LOGINREC instead of LOGIN7, a capability
negotiation, SQL sent as a LANGUAGE token in a normal packet, and results described by ROWFMT rather than
COLMETADATA. Cleartext login only. Read-oriented for sqlmap: execute() takes a fully-formed query string,
binary values come back as bytes (sqlmap hex-encodes them).

Two encodings look like their Microsoft namesakes and are not: DECIMAL/NUMERIC carries a big-endian
magnitude with 1 meaning *negative* (Microsoft is little-endian with 1 meaning positive), and DONE reports
a 4-byte row count (Microsoft uses 8).
"""

import os
import re
import socket
import struct

from extra.dbwire import DatabaseError
from extra.dbwire import DataError
from extra.dbwire import IntegrityError
from extra.dbwire import InterfaceError
from extra.dbwire import NotSupportedError
from extra.dbwire import OperationalError
from extra.dbwire import handshake_done
from extra.dbwire import keepalive
from extra.dbwire import ProgrammingError

# the packet framing is byte-identical to the Microsoft dialect - only what travels inside it differs
from extra.dbwire.tds import _decode_datetime
from extra.dbwire.tds import _decode_money
from extra.dbwire.tds import _decode_smalldatetime
from extra.dbwire.tds import _read_message
from extra.dbwire.tds import _send_message

_PKT_LOGIN = 0x02
_PKT_NORMAL = 0x0f
_LOGIN_CHUNK = 504    # the login travels in 512-byte packets: the server's buffer is not negotiated yet
_PACKET_SIZE = 2048   # ASE's default 'max network packet size'; a bigger request is negotiated down
_HEADER_SIZE = 8

# tokens
_TOKEN_LANGUAGE = 0x21
_TOKEN_ROWFMT = 0xee
_TOKEN_ROWFMT2 = 0x61
_TOKEN_ROW = 0xd1
_TOKEN_CAPABILITY = 0xe2
_TOKEN_ENVCHANGE = 0xe3
_TOKEN_EED = 0xe5
_TOKEN_RETURNSTATUS = 0x79
_TOKEN_LOGOUT = 0x71
_TOKEN_DONE = frozenset((0xfd, 0xfe, 0xff))  # DONE / DONEPROC / DONEINPROC
_DONE_COUNT = 0x0010                         # DONE status bit: the row count is meaningful
_ENV_PACKET_SIZE = 4                         # ENVCHANGE type: the server's answer to the requested size

# SYB* datatype codes. Fixed-length types carry no per-value length; everything else is length-prefixed,
# and a zero length means NULL (TDS 5 cannot tell an empty string from NULL - neither can ASE itself).
_T_INT1, _T_BIT, _T_INT2, _T_INT4, _T_INT8 = 0x30, 0x32, 0x34, 0x38, 0xbf
_T_REAL, _T_FLT8, _T_MONEY, _T_MONEY4 = 0x3b, 0x3e, 0x3c, 0x7a
_T_DATETIME, _T_DATETIME4, _T_DATE, _T_TIME = 0x3d, 0x3a, 0x31, 0x33
_T_INTN, _T_FLTN, _T_MONEYN, _T_DATETIMN, _T_DATEN, _T_TIMEN = 0x26, 0x6d, 0x6e, 0x6f, 0x7b, 0x93
_T_DECIMAL, _T_NUMERIC = 0x6a, 0x6c
_T_CHAR, _T_VARCHAR, _T_BINARY, _T_VARBINARY, _T_NVARCHAR = 0x2f, 0x27, 0x2d, 0x25, 0x67
_T_TEXT, _T_IMAGE, _T_UNITEXT = 0x23, 0x22, 0xae
_T_LONGBINARY, _T_LONGCHAR = 0xe1, 0xaf
_T_BIGDATETIME, _T_BIGTIME = 0xbb, 0xbc
_T_BIGDATETIMEN, _T_BIGTIMEN = 0xbd, 0xbe
_T_VOID = 0x1f

_FIXED_LENGTH = {
    _T_INT1: 1, _T_BIT: 1, _T_INT2: 2, _T_INT4: 4, _T_INT8: 8, _T_REAL: 4, _T_FLT8: 8,
    _T_MONEY: 8, _T_MONEY4: 4, _T_DATETIME: 8, _T_DATETIME4: 4, _T_DATE: 4, _T_TIME: 4,
    _T_BIGDATETIME: 8, _T_BIGTIME: 8, _T_VOID: 0,
}
_BLOB_TYPES = frozenset((_T_TEXT, _T_IMAGE, _T_UNITEXT))          # textptr + timestamp + 4-byte length
_LONG_TYPES = frozenset((_T_LONGBINARY, _T_LONGCHAR))             # 4-byte length
_BINARY_TYPES = frozenset((_T_BINARY, _T_VARBINARY, _T_IMAGE))
_DECIMAL_TYPES = frozenset((_T_DECIMAL, _T_NUMERIC))
# univarchar/unichar/unitext are carried as LONGBINARY/UNITEXT holding UTF-16 - only the user type says so
_UNICODE_USERTYPES = frozenset((34, 35, 36))
# a client that does not claim the date/time/bigdatetime capabilities gets those columns converted to a
# plain datetime, which is lossless but would render a date as '... 00:00:00'. The user type survives the
# conversion, so it is what says how much of the value the column actually holds.
_USERTYPE_DATE = 37
_USERTYPE_TIME = frozenset((38, 49))

_IDENTIFIER = re.compile(r"^[A-Za-z_#][A-Za-z0-9_#$]*$")

def _u8(data, off):
    return struct.unpack("<B", data[off:off + 1])[0]

def _u16(data, off):
    return struct.unpack("<H", data[off:off + 2])[0]

def _i32(data, off):
    return struct.unpack("<i", data[off:off + 4])[0]

def _login_string(value, size):
    # fixed-width field: `size` bytes of (truncated, NUL-padded) text followed by the actual length
    data = (value or "").encode("utf-8")[:size]
    return data + b"\x00" * (size - len(data)) + struct.pack("<B", len(data))

def _loginrec(host, user, password, appname, servername, charset, packetsize):
    """
    The TDS 5.0 LOGINREC: one fixed 568-byte record, then a 35-byte CAPABILITY token.

    Field order and widths mirror what ASE's own Open Client puts on the wire. The two reserved runs are
    spare in every implementation that documents them (Open Client sets one byte inside the second run,
    ASE accepts the record without it), so they go out as zeros rather than as an unexplained constant.
    """

    out = _login_string(host, 30)                       # client host name
    out += _login_string(user, 30)                      # user name
    out += _login_string(password, 30)                  # password (cleartext)
    out += _login_string("%d" % os.getpid(), 30)         # client process id, as text
    # number/char/date byte orders, then: notify on USE, refuse dump-load & bulk-copy, interface, network
    out += struct.pack("<9B", 3, 1, 6, 10, 9, 1, 1, 0, 0)
    out += b"\x00" * 7                                  # spare
    out += _login_string(appname, 30)                   # application name
    out += _login_string(servername, 30)                # server name
    remote = b"\x00" + struct.pack("<B", len(password or "")) + (password or "").encode("utf-8")
    out += remote + b"\x00" * (255 - len(remote)) + struct.pack("<B", len(remote))  # remote passwords
    out += struct.pack("<4B", 5, 0, 0, 0)               # TDS version 5.0.0.0
    out += _login_string("dbwire", 10)                  # library name
    out += struct.pack("<4B", 1, 0, 0, 0)               # library version
    out += struct.pack("<3B", 0, 0x0d, 0x11)            # auto-convert short, float4 & date4 formats
    out += b"\x00"                                      # reserved
    out += _login_string("", 30)                        # language (empty -> the server default)
    out += b"\x00" * 13                                 # notify-on-language-change, security & HA fields
    out += _login_string(charset, 30)                   # client character set
    out += b"\x00"                                      # notify on character-set change
    out += _login_string("%d" % packetsize, 6)          # network packet size, as text
    out += b"\x00" * 4                                  # spare

    # capability negotiation: request bits say what the client can do, response bits what it wants back.
    # All-zero is the baseline dialect - the wide/streaming formats a fallback client has no use for are
    # exactly the ones it must not claim, or the server starts answering in them.
    capability = struct.pack("<3B", _TOKEN_CAPABILITY, 32, 0)
    capability += struct.pack("<2B", 1, 14) + b"\x00" * 14
    capability += struct.pack("<2B", 2, 14) + b"\x00" * 14
    return out + capability

class _Column(object):
    __slots__ = ("name", "type", "size", "scale", "usertype")

def _parse_rowfmt(data, off, length, codec):
    end = off + length
    count = _u16(data, off); off += 2
    columns = []
    for _ in range(count):
        col = _Column()
        namelen = _u8(data, off); off += 1
        col.name = data[off:off + namelen].decode(codec, "replace"); off += namelen
        off += 1                                        # status (nullability - the value length says it)
        col.usertype = _i32(data, off); off += 4
        col.type = _u8(data, off); off += 1
        col.size, col.scale = _FIXED_LENGTH.get(col.type, 0), 0
        if col.type in _DECIMAL_TYPES:
            col.size = _u8(data, off)
            col.scale = _u8(data, off + 2)              # precision (off + 1) is not needed to decode
            off += 3
        elif col.type in _BLOB_TYPES:
            col.size = _i32(data, off); off += 4
            off += 2 + _u16(data, off)                  # the blob's table name
        elif col.type in _LONG_TYPES:
            col.size = _i32(data, off); off += 4
        elif col.type not in _FIXED_LENGTH:
            col.size = _u8(data, off); off += 1
        off += 1 + _u8(data, off)                       # locale
        columns.append(col)
    if off != end:
        raise InterfaceError("malformed ROWFMT token (%d columns did not fill %d bytes)" % (count, length))
    return columns, off

def _decode_numeric(raw, scale):
    # sign byte then a BIG-endian magnitude, and 1 means NEGATIVE (the Microsoft encoding is the mirror
    # image of this: little-endian, 1 == positive)
    magnitude = 0
    for b in bytearray(raw[1:]):
        magnitude = (magnitude << 8) | b
    value = -magnitude if bytearray(raw)[0] else magnitude
    if scale:
        text = "%0*d" % (scale + 1, abs(value))
        return ("-" if value < 0 else "") + text[:-scale] + "." + text[-scale:]
    return "%d" % value

def _decode_date(raw):
    import datetime
    return "%s" % (datetime.date(1900, 1, 1) + datetime.timedelta(days=_i32(raw, 0)))

def _decode_time(raw):
    import datetime
    ticks = struct.unpack("<I", raw)[0]                 # 300ths of a second since midnight
    return "%s" % (datetime.datetime(1900, 1, 1) + datetime.timedelta(milliseconds=ticks * 10.0 / 3.0)).time()

def _decode_bigdatetime(raw, time_only=False):
    import datetime
    micros = struct.unpack("<Q", raw)[0]                # microseconds since 0001-01-01 00:00:00
    value = datetime.datetime(1, 1, 1) + datetime.timedelta(microseconds=micros)
    return "%s" % (value.time() if time_only else value)

def _decode_value(col, raw, codec):
    t = col.type
    if t in (_T_INT1, _T_BIT) or (t == _T_INTN and len(raw) == 1):
        value = bytearray(raw)[0]                       # tinyint is unsigned; bit is 0/1
        return "%d" % value
    if t == _T_INT2 or (t == _T_INTN and len(raw) == 2):
        return "%d" % struct.unpack("<h", raw)[0]
    if t == _T_INT4 or (t == _T_INTN and len(raw) == 4):
        return "%d" % struct.unpack("<i", raw)[0]
    if t == _T_INT8 or (t == _T_INTN and len(raw) == 8):
        return "%d" % struct.unpack("<q", raw)[0]
    if t in (_T_REAL, _T_FLT8, _T_FLTN):
        return repr(struct.unpack("<f" if len(raw) == 4 else "<d", raw)[0])
    if t in (_T_MONEY, _T_MONEY4, _T_MONEYN):
        return _decode_money(raw)
    if t in _DECIMAL_TYPES:
        return _decode_numeric(raw, col.scale)
    if t in (_T_DATETIME, _T_DATETIME4, _T_DATETIMN):
        text = _decode_datetime(raw) if len(raw) == 8 else _decode_smalldatetime(raw)
        if col.usertype == _USERTYPE_DATE:
            return text.split(" ")[0]
        if col.usertype in _USERTYPE_TIME:
            return text.split(" ")[1]
        return text
    if t in (_T_DATE, _T_DATEN):
        return _decode_date(raw)
    if t in (_T_TIME, _T_TIMEN):
        return _decode_time(raw)
    if t in (_T_BIGDATETIME, _T_BIGDATETIMEN):
        return _decode_bigdatetime(raw)
    if t in (_T_BIGTIME, _T_BIGTIMEN):
        return _decode_bigdatetime(raw, time_only=True)
    if t in _BINARY_TYPES:
        return raw                                      # sqlmap hex-encodes binary columns
    if t == _T_UNITEXT or col.usertype in _UNICODE_USERTYPES:
        return raw.decode("utf-16-le", "replace")
    if t in (_T_CHAR, _T_VARCHAR, _T_NVARCHAR, _T_LONGCHAR, _T_TEXT):
        return raw.decode(codec, "replace")
    return raw      # LONGBINARY that is not unichar, a locator handle, an unmapped type: bytes, not a guess

def _read_value(col, data, off, codec):
    if col.type in _FIXED_LENGTH:
        size = _FIXED_LENGTH[col.type]
        raw, off = data[off:off + size], off + size
        if not size:
            return None, off
    elif col.type in _BLOB_TYPES:
        ptrlen = _u8(data, off); off += 1
        if not ptrlen:
            return None, off                            # no text pointer -> NULL
        off += ptrlen + 8                               # text pointer + timestamp
        length = _i32(data, off); off += 4
        raw, off = data[off:off + length], off + length
    elif col.type in _LONG_TYPES:
        length = _i32(data, off); off += 4
        if not length:
            return None, off
        raw, off = data[off:off + length], off + length
    else:
        length = _u8(data, off); off += 1
        if not length:
            return None, off
        raw, off = data[off:off + length], off + length
    return _decode_value(col, raw, codec), off

def _eed(data, off, codec):
    # EED: number(4) state(1) class(1) sqlstate, status(1) transtate(2) message, server, procedure, line
    number = _i32(data, off)
    severity = _u8(data, off + 5)
    pos = off + 6
    pos += 1 + _u8(data, pos)                           # SQLSTATE
    pos += 1 + 2                                        # status + transaction state
    length = _u16(data, pos); pos += 2
    return number, severity, data[pos:pos + length].decode(codec, "replace").strip()

def _raise_server_error(number, message):
    if number in (2601, 2615, 2627, 1105, 546, 547):    # duplicate key/row, constraint, foreign key
        raise IntegrityError(message)
    if number in (247, 249, 257, 260, 264, 512, 8115):  # conversion, overflow, arithmetic
        raise DataError(message)
    raise ProgrammingError(message)

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
        self.description, self._rows, affected = self.connection._query(query)
        self.rowcount = len(self._rows) if self.description is not None else (affected if affected is not None else -1)
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
    def __init__(self, sock, codec):
        self._sock = sock
        self._codec = codec
        # a packet larger than the size agreed at login is not an error the server reports - it drops the
        # connection, so every send has to be chopped to what the login negotiated (ENVCHANGE 4 below)
        self._chunk = _PACKET_SIZE - _HEADER_SIZE

    def cursor(self):
        return Cursor(self)

    def commit(self):
        pass  # sqlmap issues autonomous statements; ASE is in unchained (auto-commit) mode by default

    def rollback(self):
        pass

    def close(self):
        try:
            _send_message(self._sock, _PKT_NORMAL, struct.pack("<2B", _TOKEN_LOGOUT, 0))
        except Exception:
            pass
        try:
            self._sock.close()
        except Exception:
            pass

    def _query(self, query):
        # LANGUAGE token: length covers the status byte and the (single-byte encoded) statement text
        text = query.encode(self._codec, "replace")
        token = struct.pack("<BiB", _TOKEN_LANGUAGE, len(text) + 1, 0) + text
        _send_message(self._sock, _PKT_NORMAL, token, self._chunk)
        try:
            return self._read_response()
        except (struct.error, IndexError, ValueError, KeyError) as ex:
            raise InterfaceError("malformed server response: %s" % ex)

    def _read_response(self, login=False):
        data = _read_message(self._sock)
        off, columns, rows, description, affected = 0, [], [], None, None
        error = None
        while off < len(data):
            token = _u8(data, off); off += 1
            if token == _TOKEN_ROWFMT:
                length = _u16(data, off); off += 2
                columns, off = _parse_rowfmt(data, off, length, self._codec)
                description = [(c.name, c.type, None, None, None, c.scale, None) for c in columns]
                rows, affected = [], None
            elif token == _TOKEN_ROW:
                row = []
                for col in columns:
                    value, off = _read_value(col, data, off, self._codec)
                    row.append(value)
                rows.append(tuple(row))
            elif token in _TOKEN_DONE:
                status, _transtate, count = struct.unpack("<HHi", data[off:off + 8]); off += 8
                if status & _DONE_COUNT:
                    affected = count if affected is None else affected + count
            elif token == _TOKEN_EED:
                length = _u16(data, off)
                number, severity, message = _eed(data, off + 2, self._codec)
                if severity > 10:               # 10 and below are informational (e.g. 'Changed database')
                    error = (number, "(remote) %s" % message)
                off += 2 + length
            elif token == _TOKEN_ENVCHANGE:
                length = _u16(data, off)
                if _u8(data, off + 2) == _ENV_PACKET_SIZE:
                    size = data[off + 4:off + 4 + _u8(data, off + 3)]
                    self._chunk = max(_LOGIN_CHUNK, int(size) - _HEADER_SIZE)
                off += 2 + length
            elif token == _TOKEN_RETURNSTATUS:
                off += 4
            elif token == _TOKEN_ROWFMT2:
                raise NotSupportedError("the server answered with the wide ROWFMT2 format")
            else:
                off += 2 + _u16(data, off)      # every other TDS 5 token is 2-byte length prefixed
        if error is not None:
            if login:
                raise OperationalError(error[1])
            _raise_server_error(*error)
        return description, rows, affected

def connect(host=None, port=5000, user=None, password=None, database=None, connect_timeout=None, **kwargs):
    charset, codec = kwargs.get("charset", "utf8"), "utf-8"
    try:
        sock = socket.create_connection((host or "localhost", int(port or 5000)), timeout=connect_timeout)
        keepalive(sock)
    except (socket.error, socket.timeout) as ex:
        raise OperationalError("could not connect to '%s:%s' (%s)" % (host, port, ex))

    connection = Connection(sock, codec)
    try:
        login = _loginrec("dbwire", user or "", password or "", "dbwire", host or "localhost", charset, _PACKET_SIZE)
        _send_message(sock, _PKT_LOGIN, login, _LOGIN_CHUNK)
        connection._read_response(login=True)
        handshake_done(sock)
        if database:
            if not _IDENTIFIER.match(database):
                raise ProgrammingError("unsupported database name %r" % database)
            connection._query("USE %s" % database)
    except (DatabaseError, InterfaceError):
        connection.close()
        raise
    except Exception as ex:
        connection.close()
        raise OperationalError("Sybase login failed (%s)" % ex)
    return connection
