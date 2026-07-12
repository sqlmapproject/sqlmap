#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
Minimal pure-python TDS (Tabular Data Stream) client for Microsoft SQL Server / Sybase (stdlib only).

Cleartext login only (TDS pre-login encryption negotiated to NOT_SUP); a server that forces encryption
would need TLS-in-TDS which is out of scope for the dependency-free client. Implements PRELOGIN, LOGIN7,
SQL batch, and decoding of the common column types (int/bit/float/money/decimal, (n)char/(n)varchar and
their MAX/PLP forms, binary, guid, datetime family) to text (binary columns are returned as raw bytes so
sqlmap hex-encodes them).
"""

import socket
import struct

from extra.dbwire import DatabaseError
from extra.dbwire import InterfaceError
from extra.dbwire import NotSupportedError
from extra.dbwire import OperationalError
from extra.dbwire import ProgrammingError

_MAX_MESSAGE_LENGTH = 0x40000000

# packet types
_PKT_SQL_BATCH = 0x01
_PKT_LOGIN7 = 0x10
_PKT_PRELOGIN = 0x12
_STATUS_EOM = 0x01

def _u8(data, off):
    return struct.unpack("<B", data[off:off + 1])[0]

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise InterfaceError("connection closed by server")
        buf += chunk
    return buf

def _send_message(sock, mtype, data):
    # split into <= 4096-byte packets (8-byte header + <=4088 data); only the last carries the EOM status bit
    chunk_size = 4088
    packet_id = 0
    off = 0
    while True:
        chunk = data[off:off + chunk_size]
        off += chunk_size
        last = off >= len(data)
        header = struct.pack(">BBHHBB", mtype, _STATUS_EOM if last else 0x00, len(chunk) + 8, 0, packet_id & 0xff, 0)
        sock.sendall(header + chunk)
        packet_id += 1
        if last:
            break

def _read_message(sock):
    # reassemble a full TDS message across packets (EOM status bit marks the last)
    body = b""
    while True:
        header = _recvn(sock, 8)
        mtype, status, length = struct.unpack(">BBH", header[:4])
        if length < 8 or length > _MAX_MESSAGE_LENGTH:
            raise InterfaceError("invalid TDS packet length (%d)" % length)
        body += _recvn(sock, length - 8)
        if status & _STATUS_EOM:
            break
    return body

# ---- PRELOGIN ----------------------------------------------------------------------------------------

def _prelogin(sock):
    ver = struct.pack(">IH", 0x11000000, 0)
    enc = b"\x02"  # ENCRYPT_NOT_SUP
    tokens = b"\x00" + struct.pack(">HH", 11, len(ver))
    tokens += b"\x01" + struct.pack(">HH", 11 + len(ver), len(enc))
    tokens += b"\xff"
    _send_message(sock, _PKT_PRELOGIN, tokens + ver + enc)
    body = _read_message(sock)
    off = 0
    while off < len(body) and _u8(body, off) != 0xff:
        token = _u8(body, off)
        toff, tlen = struct.unpack(">HH", body[off + 1:off + 5])
        if token == 0x01 and _u8(body, toff) == 0x03:  # server requires encryption
            raise NotSupportedError("server requires TDS encryption; the dependency-free client supports cleartext only")
        off += 5

# ---- LOGIN7 ------------------------------------------------------------------------------------------

def _encode_password(password):
    out = bytearray()
    for b in bytearray(password.encode("utf-16-le")):
        b = ((b << 4) & 0xf0) | ((b >> 4) & 0x0f)
        out.append(b ^ 0xa5)
    return bytes(out)

def _login7(sock, user, password, database, hostname="dbwire", appname="dbwire"):
    fields = [
        hostname.encode("utf-16-le"),
        (user or "").encode("utf-16-le"),
        _encode_password(password or ""),
        appname.encode("utf-16-le"),
        b"",                              # server name
        b"",                              # (extension / unused)
        "dbwire".encode("utf-16-le"),     # client interface name
        b"",                              # language
        (database or "").encode("utf-16-le"),
    ]
    char_counts = [6, len(user or ""), len(password or ""), 6, 0, 0, 6, 0, len(database or "")]

    base = 94  # fixed header (36) + offset/length block (58)
    var, offsets, cursor = b"", b"", base
    for i, data in enumerate(fields):
        offsets += struct.pack("<HH", cursor if data else base, char_counts[i])
        var += data
        cursor += len(data)

    offsets += b"\x00" * 6                       # ClientID (MAC)
    offsets += struct.pack("<HH", base, 0)       # SSPI
    offsets += struct.pack("<HH", base, 0)       # AtchDBFile
    offsets += struct.pack("<HH", base, 0)       # ChangePassword
    offsets += struct.pack("<I", 0)              # cbSSPILong

    header = struct.pack("<I", 0x74000004)       # TDS 7.4
    header += struct.pack("<I", 4096)            # packet size
    header += struct.pack("<I", 0)               # client prog version
    header += struct.pack("<I", 0)               # client PID
    header += struct.pack("<I", 0)               # connection id
    header += struct.pack("<BBBB", 0, 0, 0, 0)   # option flags 1/2, type flags, option flags 3
    header += struct.pack("<i", 0)               # client time zone
    header += struct.pack("<I", 0)               # client LCID

    payload = header + offsets + var
    payload = struct.pack("<I", len(payload) + 4) + payload  # prepend total length
    _send_message(sock, _PKT_LOGIN7, payload)
    _parse_tokens(sock, login=True)

# ---- token stream + type decoding --------------------------------------------------------------------

def _read_us_varchar(data, off):
    (n,) = struct.unpack("<B", data[off:off + 1])
    return data[off + 1:off + 1 + n * 2].decode("utf-16-le", "replace"), off + 1 + n * 2

def _decode_datetime(raw):
    days, ticks = struct.unpack("<iI", raw)
    import datetime
    return "%s" % (datetime.datetime(1900, 1, 1) + datetime.timedelta(days=days, milliseconds=ticks * 10.0 / 3.0))

class _Column(object):
    __slots__ = ("name", "type", "size", "scale", "binary")

def _parse_type_info(data, off):
    col = _Column()
    col.type = _u8(data, off); off += 1
    col.size, col.scale, col.binary = 0, 0, False
    t = col.type
    if t in (0x30, 0x32, 0x34, 0x38, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x7a, 0x7f, 0x1f):
        pass  # fixed-length types, size implied by type
    elif t in (0x26, 0x68, 0x6d, 0x6e, 0x6f, 0x24, 0x2e, 0x37):  # INTN/BITN/FLTN/MONEYN/DATETIMN/GUID
        col.size = _u8(data, off); off += 1
    elif t in (0x6a, 0x6c):  # DECIMALN / NUMERICN
        col.size = _u8(data, off); off += 1
        off += 1  # precision
        col.scale = _u8(data, off); off += 1
    elif t in (0xa7, 0xaf, 0xe7, 0xef):  # (BIG)VARCHAR/CHAR, N(VAR)CHAR
        col.size = struct.unpack("<H", data[off:off + 2])[0]; off += 2
        off += 5  # collation
    elif t in (0xa5, 0xad):  # (BIG)VARBINARY / BINARY
        col.size = struct.unpack("<H", data[off:off + 2])[0]; off += 2
        col.binary = True
    elif t in (0x28, 0x29, 0x2a, 0x2b):  # DATE/TIME/DATETIME2/DATETIMEOFFSET
        if t != 0x28:
            col.scale = _u8(data, off); off += 1
    elif t in (0x23, 0x63, 0x22):  # TEXT/NTEXT/IMAGE
        col.size = struct.unpack("<i", data[off:off + 4])[0]; off += 4
        if t in (0x23, 0x63):
            off += 5  # collation
        col.binary = (t == 0x22)
        # table name (num parts + parts) follows in COLMETADATA for these; handled by caller via name read
    else:
        raise NotSupportedError("unsupported TDS column type 0x%02x" % t)
    return col, off

def _read_plp(data, off):
    # PLP (partially-length-prefixed) body: 8-byte total len (or 0xFF..FF NULL / 0xFF..FE unknown) then chunks
    total = struct.unpack("<Q", data[off:off + 8])[0]; off += 8
    if total == 0xffffffffffffffff:
        return None, off
    out = b""
    while True:
        (clen,) = struct.unpack("<I", data[off:off + 4]); off += 4
        if clen == 0:
            break
        out += data[off:off + clen]; off += clen
    return out, off

def _decode_value(col, data, off):
    t = col.type
    # fixed-length
    if t == 0x1f:
        return None, off
    if t == 0x30:
        return str(_u8(data, off)), off + 1
    if t == 0x34:
        return str(struct.unpack("<h", data[off:off + 2])[0]), off + 2
    if t == 0x38:
        return str(struct.unpack("<i", data[off:off + 4])[0]), off + 4
    if t == 0x7f:
        return str(struct.unpack("<q", data[off:off + 8])[0]), off + 8
    if t == 0x32:
        return ("1" if _u8(data, off) else "0"), off + 1
    if t == 0x3b:
        return repr(struct.unpack("<f", data[off:off + 4])[0]), off + 4
    if t == 0x3e:
        return repr(struct.unpack("<d", data[off:off + 8])[0]), off + 8
    if t == 0x7a:  # MONEY4 (4 bytes)
        return "%.4f" % (struct.unpack("<i", data[off:off + 4])[0] / 10000.0), off + 4
    if t == 0x3c:  # MONEY (8 bytes: high 4 then low 4)
        hi, lo = struct.unpack("<iI", data[off:off + 8])
        return "%.4f" % (((hi << 32) | lo) / 10000.0), off + 8
    if t == 0x3d:  # DATETIME (8 bytes)
        return _decode_datetime(data[off:off + 8]), off + 8
    if t == 0x3a:  # DATETIM4 / smalldatetime (2-byte days since 1900 + 2-byte minutes)
        import datetime
        days, mins = struct.unpack("<HH", data[off:off + 4])
        return "%s" % (datetime.datetime(1900, 1, 1) + datetime.timedelta(days=days, minutes=mins)), off + 4

    # variable-length with a length prefix
    if t in (0xa7, 0xaf, 0xe7, 0xef, 0xa5, 0xad):
        if col.size == 0xffff:  # MAX types use PLP
            raw, off = _read_plp(data, off)
        else:
            (n,) = struct.unpack("<H", data[off:off + 2]); off += 2
            if n == 0xffff:
                return None, off
            raw, off = data[off:off + n], off + n
        if raw is None:
            return None, off
        if t in (0xa5, 0xad):
            return raw, off  # binary -> raw bytes
        if t in (0xe7, 0xef):
            return raw.decode("utf-16-le", "replace"), off
        return raw.decode("latin-1"), off  # (var)char is the collation's single-byte codepage; latin-1 round-trips every byte losslessly

    if t in (0x23, 0x63, 0x22):  # TEXT/NTEXT/IMAGE: 1-byte textptr len (0 = NULL) then textptr+timestamp then 4-byte len
        ptr_len = _u8(data, off); off += 1
        if ptr_len == 0:
            return None, off
        off += ptr_len + 8
        (n,) = struct.unpack("<i", data[off:off + 4]); off += 4
        raw, off = data[off:off + n], off + n
        if t == 0x22:
            return raw, off
        if t == 0x63:
            return raw.decode("utf-16-le", "replace"), off
        return raw.decode("latin-1"), off  # TEXT is single-byte codepage; latin-1 is lossless

    # nullable / length-prefixed numeric & misc
    (n,) = struct.unpack("<B", data[off:off + 1]); off += 1
    if n == 0:
        return None, off
    raw, off = data[off:off + n], off + n
    if t == 0x26:  # INTN (size 1 is unsigned tinyint; 2/4/8 are signed)
        return str(struct.unpack({1: "<B", 2: "<h", 4: "<i", 8: "<q"}[n], raw)[0]), off
    if t == 0x68:  # BITN
        return ("1" if bytearray(raw)[0] else "0"), off
    if t == 0x6d:  # FLTN
        return repr(struct.unpack("<f" if n == 4 else "<d", raw)[0]), off
    if t in (0x6e, 0x3d, 0x7a):  # MONEYN / MONEY / MONEY4
        if n == 4:
            v = struct.unpack("<i", raw)[0]
        else:
            hi, lo = struct.unpack("<ii", raw)
            v = (hi << 32) | (lo & 0xffffffff)
        return "%.4f" % (v / 10000.0), off
    if t in (0x6a, 0x6c):  # DECIMALN / NUMERICN
        sign = bytearray(raw)[0]
        magnitude = 0
        for b in reversed(bytearray(raw[1:])):
            magnitude = (magnitude << 8) | b
        value = magnitude if sign else -magnitude
        if col.scale:
            s = "%0*d" % (col.scale + 1, value if value >= 0 else -value)
            s = ("-" if value < 0 else "") + s[:-col.scale] + "." + s[-col.scale:]
            return s, off
        return str(value), off
    if t == 0x24:  # GUID
        a, b, c = struct.unpack("<IHH", raw[:8])
        d = raw[8:]
        return ("%08X-%04X-%04X-%s-%s" % (a, b, c, "".join("%02X" % x for x in bytearray(d[:2])), "".join("%02X" % x for x in bytearray(d[2:])))), off
    if t == 0x6f:  # DATETIMN (n=8 datetime, n=4 smalldatetime)
        if n == 8:
            return _decode_datetime(raw), off
        import datetime
        days, mins = struct.unpack("<HH", raw)
        return "%s" % (datetime.datetime(1900, 1, 1) + datetime.timedelta(days=days, minutes=mins)), off
    if t == 0x28:  # DATE (3 bytes: days since 0001-01-01)
        import datetime
        days = struct.unpack("<I", raw[:3] + b"\x00")[0]
        return "%s" % (datetime.date(1, 1, 1) + datetime.timedelta(days=days)), off
    if t in (0x2a, 0x29):  # DATETIME2 (time + 3-byte date) / TIME (time only), time = scaled 10^-scale s units
        import datetime
        date_bytes = raw[-3:] if t == 0x2a else b"\x00\x00\x00"
        time_bytes = raw[:-3] if t == 0x2a else raw
        days = struct.unpack("<I", date_bytes + b"\x00")[0]
        ticks = struct.unpack("<Q", time_bytes + b"\x00" * (8 - len(time_bytes)))[0]
        seconds = ticks / (10.0 ** (col.scale or 7))
        base = datetime.datetime(1, 1, 1) + datetime.timedelta(days=days, seconds=seconds)
        return ("%s" % base if t == 0x2a else "%s" % base.time()), off
    # unknown date/time layout: return the raw hex as a last resort (never desyncs)
    return "".join("%02x" % x for x in bytearray(raw)), off

def _parse_tokens(sock, login=False):
    data = _read_message(sock)
    off, columns, rows, description, error = 0, [], [], None, None
    while off < len(data):
        token = _u8(data, off); off += 1
        if token == 0x81:  # COLMETADATA (a new result set: drop any prior rows so only the last is returned)
            (count,) = struct.unpack("<H", data[off:off + 2]); off += 2
            columns, rows = [], []
            if count == 0xffff:
                continue
            for _ in range(count):
                off += 4  # user type
                off += 2  # flags
                col, off = _parse_type_info(data, off)
                if col.type in (0x23, 0x63, 0x22):  # TEXT/NTEXT/IMAGE carry a table name before the col name
                    (numparts,) = struct.unpack("<B", data[off:off + 1]); off += 1
                    for _ in range(numparts):
                        (plen,) = struct.unpack("<H", data[off:off + 2]); off += 2 + plen * 2
                col.name, off = _read_us_varchar(data, off)
                columns.append(col)
            description = [(c.name, c.type, None, None, None, None, None) for c in columns]
        elif token == 0xd1:  # ROW
            row = []
            for col in columns:
                value, off = _decode_value(col, data, off)
                row.append(value)
            rows.append(tuple(row))
        elif token == 0xd2:  # NBCROW (null-bitmap compressed)
            nbc_len = (len(columns) + 7) // 8
            bitmap = bytearray(data[off:off + nbc_len]); off += nbc_len
            row = []
            for i, col in enumerate(columns):
                if bitmap[i // 8] & (1 << (i % 8)):
                    row.append(None)
                else:
                    value, off = _decode_value(col, data, off)
                    row.append(value)
            rows.append(tuple(row))
        elif token == 0xaa:  # ERROR
            (tlen,) = struct.unpack("<H", data[off:off + 2]); off += 2
            number = struct.unpack("<i", data[off:off + 4])[0]
            msg_off = off + 4 + 1 + 1  # number(4) state(1) class(1)
            (mlen,) = struct.unpack("<H", data[msg_off:msg_off + 2])
            error = data[msg_off + 2:msg_off + 2 + mlen * 2].decode("utf-16-le", "replace")
            off += tlen
        elif token == 0xab:  # INFO
            (tlen,) = struct.unpack("<H", data[off:off + 2]); off += 2 + tlen
        elif token == 0xad:  # LOGINACK
            (tlen,) = struct.unpack("<H", data[off:off + 2]); off += 2 + tlen
        elif token == 0xe3:  # ENVCHANGE
            (tlen,) = struct.unpack("<H", data[off:off + 2]); off += 2 + tlen
        elif token == 0x79:  # RETURNSTATUS
            off += 4
        elif token == 0xa9:  # ORDER
            (tlen,) = struct.unpack("<H", data[off:off + 2]); off += 2 + tlen
        elif token in (0xfd, 0xfe, 0xff):  # DONE / DONEPROC / DONEINPROC
            off += 12
        else:
            raise InterfaceError("unexpected TDS token 0x%02x" % token)

    if error is not None:
        if login:
            raise OperationalError("(remote) %s" % error)
        raise ProgrammingError("(remote) %s" % error)
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
        pass  # sqlmap issues autonomous statements; SET IMPLICIT_TRANSACTIONS is off by default

    def rollback(self):
        pass

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass

    def _query(self, query):
        # TDS 7.2+ SQL batch must be prefixed with ALL_HEADERS carrying the transaction descriptor header
        headers = struct.pack("<I", 22) + struct.pack("<I", 18) + struct.pack("<H", 2) + struct.pack("<Q", 0) + struct.pack("<I", 1)
        _send_message(self._sock, _PKT_SQL_BATCH, headers + query.encode("utf-16-le"))
        try:
            return _parse_tokens(self._sock)
        except (struct.error, IndexError, ValueError, KeyError) as ex:
            raise InterfaceError("malformed server response: %s" % ex)

def connect(host=None, port=1433, user=None, password=None, database=None, connect_timeout=None, **kwargs):
    try:
        sock = socket.create_connection((host or "localhost", int(port or 1433)), timeout=connect_timeout)
        sock.settimeout(None)
    except (socket.error, socket.timeout) as ex:
        raise OperationalError("could not connect to '%s:%s' (%s)" % (host, port, ex))

    try:
        _prelogin(sock)
        _login7(sock, user, password, database)
    except (DatabaseError, InterfaceError):
        try:
            sock.close()
        except Exception:
            pass
        raise
    except Exception as ex:
        try:
            sock.close()
        except Exception:
            pass
        raise OperationalError("TDS login failed (%s)" % ex)

    return Connection(sock)
