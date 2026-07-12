#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
Minimal pure-python Firebird wire-protocol client (stdlib only, no firebirdsql).

Speaks the Firebird v13-17 protocol (Firebird 3/4/5): op_connect, SRP-256 authentication, ChaCha20 (or
Arc4) wire encryption - which Firebird 4+ requires by default - then attach / transaction / prepare /
execute / fetch with XSQLDA column description and row decoding. Read-oriented for sqlmap: execute() takes
a fully-formed query string, binary/blob values come back as bytes (sqlmap hex-encodes them).
"""

import datetime
import hashlib
import os
import socket
import struct

from extra.dbwire import DatabaseError
from extra.dbwire import DataError
from extra.dbwire import IntegrityError
from extra.dbwire import InterfaceError
from extra.dbwire import NotSupportedError
from extra.dbwire import OperationalError

# operation codes
_op_connect = 1
_op_accept = 3
_op_reject = 4
_op_response = 9
_op_attach = 19
_op_detach = 21
_op_transaction = 29
_op_commit_retaining = 50
_op_rollback_retaining = 86
_op_get_segment = 36
_op_close_blob = 39
_op_open_blob2 = 56
_op_allocate_statement = 62
_op_execute = 63
_op_fetch = 65
_op_fetch_response = 66
_op_free_statement = 67
_op_prepare_statement = 68
_op_info_sql = 70
_op_dummy = 71
_op_cont_auth = 92
_op_crypt = 96
_op_accept_data = 94
_op_cond_accept = 98

# CNCT parameter codes
_CNCT_user = 1
_CNCT_host = 4
_CNCT_user_verification = 6
_CNCT_specific_data = 7
_CNCT_plugin_name = 8
_CNCT_login = 9
_CNCT_plugin_list = 10
_CNCT_client_crypt = 11

# database / transaction parameter block items
_isc_dpb_version1 = 1
_isc_dpb_user_name = 28
_isc_dpb_lc_ctype = 48
_isc_dpb_process_id = 71
_isc_dpb_process_name = 74
_isc_tpb_version3 = 3
_isc_tpb_wait = 6
_isc_tpb_write = 9
_isc_tpb_read_committed = 15
_isc_tpb_rec_version = 17

# isc_info_sql_* describe items
_isc_info_end = 1
_isc_info_truncated = 2
_isc_info_sql_select = 4
_isc_info_sql_describe_vars = 7
_isc_info_sql_describe_end = 8
_isc_info_sql_sqlda_seq = 9
_isc_info_sql_type = 11
_isc_info_sql_sub_type = 12
_isc_info_sql_scale = 13
_isc_info_sql_length = 14
_isc_info_sql_null_ind = 15
_isc_info_sql_field = 16
_isc_info_sql_relation = 17
_isc_info_sql_owner = 18
_isc_info_sql_alias = 19
_isc_info_sql_sqlda_start = 20
_isc_info_sql_stmt_type = 21
_INFO_SQL_SELECT_DESCRIBE_VARS = bytes(bytearray([
    _isc_info_sql_select, _isc_info_sql_describe_vars, _isc_info_sql_sqlda_seq,
    _isc_info_sql_type, _isc_info_sql_sub_type, _isc_info_sql_scale, _isc_info_sql_length,
    _isc_info_sql_null_ind, _isc_info_sql_field, _isc_info_sql_relation, _isc_info_sql_owner,
    _isc_info_sql_alias, _isc_info_sql_describe_end]))

_isc_info_sql_stmt_select = 1
_DSQL_drop = 2

# SQL type codes
_SQL_VARYING = 448
_SQL_TEXT = 452
_SQL_DOUBLE = 480
_SQL_FLOAT = 482
_SQL_LONG = 496
_SQL_SHORT = 500
_SQL_TIMESTAMP = 510
_SQL_BLOB = 520
_SQL_TIME = 560
_SQL_DATE = 570
_SQL_INT64 = 580
_SQL_INT128 = 32752
_SQL_TIMESTAMP_TZ = 32754
_SQL_TIME_TZ = 32756
_SQL_BOOLEAN = 32764
_SQL_TYPE_LENGTH = {  # fixed on-the-wire length by SQL type (VARYING is length-prefixed -> -1)
    _SQL_VARYING: -1, _SQL_SHORT: 4, _SQL_LONG: 4, _SQL_FLOAT: 4, _SQL_TIME: 4, _SQL_DATE: 4,
    _SQL_DOUBLE: 8, _SQL_TIMESTAMP: 8, _SQL_BLOB: 8, _SQL_INT64: 8, _SQL_INT128: 16,
    _SQL_TIMESTAMP_TZ: 12, _SQL_TIME_TZ: 8, _SQL_BOOLEAN: 1,
}
# per-type output BLR fragment used to describe the fetched row (see calc_blr)
_SQL_TYPE_BLR = {
    _SQL_DOUBLE: [27], _SQL_FLOAT: [10], _SQL_DATE: [12], _SQL_TIME: [13], _SQL_TIMESTAMP: [35],
    _SQL_BLOB: [9, 0], _SQL_BOOLEAN: [23], _SQL_TIME_TZ: [28], _SQL_TIMESTAMP_TZ: [29],
}

# status-vector argument tags
_isc_arg_end = 0
_isc_arg_gds = 1
_isc_arg_string = 2
_isc_arg_number = 4
_isc_arg_interpreted = 5
_isc_arg_sql_state = 19
_GDS_INTEGRITY = frozenset((335544838, 335544879, 335544880, 335544466, 335544665, 335544347, 335544558))
_GDS_DATA = frozenset((335544321,))
_GDS_WARNING = 335544434

# SRP-6a group used by Firebird (fixed 1024-bit prime, generator 2)
_SRP_N = int("E67D2E994B2F900C3F41F08F5BB2627ED0D49EE1FE767A52EFCD565CD6E768812C3E1E9CE8F0A8BEA6CB13CD29DDE"
             "BF7A96D4A93B55D488DF099A15C89DCB0640738EB2CBDD9A8F7BAB561AB1B0DC1C6CDABF303264A08D1BCA932D1F"
             "1EE428B619D970F342ABA9A65793B8B2F041AE5364350C16F735F56ECBCA87BD57B29E7", 16)
_SRP_g = 2
_SRP_k = 1277432915985975349439481660349303019122249719989

def _minbe(n):
    # minimal big-endian bytes of a non-negative integer (matches firebirdsql long2bytes/pad for these sizes)
    out = bytearray()
    while n > 0:
        out.insert(0, n & 0xff)
        n >>= 8
    return bytes(out)

def _b2l(b):
    n = 0
    for c in bytearray(b):
        n = (n << 8) | c
    return n

def _sha1(*parts):
    h = hashlib.sha1()
    for p in parts:
        h.update(p if isinstance(p, bytes) else _minbe(p))
    return h.digest()

def _srp_client_seed():
    a = _b2l(os.urandom(16))  # client private key (128-bit)
    return pow(_SRP_g, a, _SRP_N), a

def _srp_client_proof(user, password, salt, A, B, a, hash_algo):
    # session key K (always SHA-1) then the Firebird-specific proof M (SHA-1 for Srp, SHA-256 for Srp256)
    u = _b2l(_sha1(_minbe(A), _minbe(B)))
    x = _b2l(_sha1(salt, _sha1(user, b":", password)))
    S = pow((B - _SRP_k * pow(_SRP_g, x, _SRP_N)) % _SRP_N, (a + u * x) % _SRP_N, _SRP_N)
    K = _sha1(_minbe(S))
    n1 = _b2l(_sha1(_minbe(_SRP_N)))
    n2 = _b2l(_sha1(_minbe(_SRP_g)))
    n1 = pow(n1, n2, _SRP_N)                     # NOTE: modular exponentiation, not XOR (Firebird quirk)
    n2 = _b2l(_sha1(user))
    h = hash_algo()
    for p in (_minbe(n1), _minbe(n2), salt, _minbe(A), _minbe(B), K):
        h.update(p)
    return h.digest(), K

class _ARC4(object):
    def __init__(self, key):
        s = list(range(256))
        key = bytearray(key)
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xff
            s[i], s[j] = s[j], s[i]
        self._s, self._i, self._j = s, 0, 0

    def translate(self, data):
        s, i, j, out = self._s, self._i, self._j, bytearray()
        for c in bytearray(data):
            i = (i + 1) & 0xff
            j = (j + s[i]) & 0xff
            s[i], s[j] = s[j], s[i]
            out.append(c ^ s[(s[i] + s[j]) & 0xff])
        self._i, self._j = i, j
        return bytes(out)

class _ChaCha20(object):
    _SIGMA = b"expand 32-byte k"

    def __init__(self, key, nonce):
        self._nonce = nonce
        self._counter = 0
        block = self._SIGMA + key + self._ctr_bytes() + nonce
        self._state = list(struct.unpack("<16L", block))
        self._make_block()

    def _ctr_bytes(self):
        return struct.pack("<Q", self._counter)[:16 - len(self._nonce)]

    def _make_block(self):
        x = list(self._state)
        for _ in range(10):
            self._qr(x, 0, 4, 8, 12); self._qr(x, 1, 5, 9, 13)
            self._qr(x, 2, 6, 10, 14); self._qr(x, 3, 7, 11, 15)
            self._qr(x, 0, 5, 10, 15); self._qr(x, 1, 6, 11, 12)
            self._qr(x, 2, 7, 8, 13); self._qr(x, 3, 4, 9, 14)
        self._block = struct.pack("<16L", *[(x[i] + self._state[i]) & 0xffffffff for i in range(16)])
        self._pos = 0

    @staticmethod
    def _qr(x, a, b, c, d):
        def rot(v, n):
            return ((v << n) | (v >> (32 - n))) & 0xffffffff
        x[a] = (x[a] + x[b]) & 0xffffffff; x[d] = rot(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xffffffff; x[b] = rot(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xffffffff; x[d] = rot(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xffffffff; x[b] = rot(x[b] ^ x[c], 7)

    def translate(self, data):
        out = bytearray()
        block = bytearray(self._block)
        for c in bytearray(data):
            out.append(c ^ block[self._pos])
            self._pos += 1
            if self._pos == 64:
                self._counter += 1
                cb = self._ctr_bytes()
                self._state[12] = struct.unpack("<L", cb[:4])[0]
                if len(self._nonce) == 8:
                    self._state[13] = struct.unpack("<L", cb[4:8])[0]
                self._make_block()
                block = bytearray(self._block)
        return bytes(out)

def _guess_wire_crypt(buf):
    # parse the crypt-key callback (type/length/value items) -> (plugin, nonce)
    plugins, nonces, buf, i = [], [], bytearray(buf), 0
    while i < len(buf):
        t, ln = buf[i], buf[i + 1]
        v = bytes(buf[i + 2:i + 2 + ln])
        i += 2 + ln
        if t == 1:
            plugins = v.split()
        elif t == 3:
            nonces.append(v)
    if b"ChaCha64" in plugins:
        for s in nonces:
            if s[:9] == b"ChaCha64\x00":
                return b"ChaCha64", s[9:]
    if b"ChaCha" in plugins:
        for s in nonces:
            if s[:7] == b"ChaCha\x00":
                return b"ChaCha", s[7:7 + 12]
    if b"Arc4" in plugins:
        return b"Arc4", None
    return None, None

class _Wire(object):
    def __init__(self, sock):
        self._sock = sock
        self._rc = self._wc = None

    def set_ciphers(self, rc, wc):
        self._rc, self._wc = rc, wc

    def send(self, data):
        self._sock.sendall(self._wc.translate(data) if self._wc else data)

    def _recv_raw(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise InterfaceError("connection closed by server")
            buf += chunk
        return buf

    def recv(self, n, align=False):
        total = n + ((4 - n % 4) % 4) if align else n
        data = self._recv_raw(total)
        if self._rc:
            data = self._rc.translate(data)
        return data[:n]

    def recv_int(self):
        return struct.unpack("!i", self.recv(4))[0]

    def recv_bytes(self):
        return self.recv(self.recv_int(), align=True)

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass

def _pack_int(v):
    return struct.pack("!i", v)

def _pack_bytes(v):
    return _pack_int(len(v)) + v + b"\x00" * ((4 - len(v) % 4) % 4)

def _le(b):
    n = 0
    for c in reversed(bytearray(b)):
        n = (n << 8) | c
    return n

def _le_signed(b):
    n = _le(b)  # info-buffer scalars are little-endian; scale is signed (usually negative)
    if b and (bytearray(b)[-1] & 0x80):
        n -= 1 << (8 * len(b))
    return n

def _b2i_signed(b):
    n = _b2l(b)
    if bytearray(b) and bytearray(b)[0] & 0x80:
        n -= 1 << (8 * len(b))
    return n

def _scaled(n, scale):
    # integer n represents n * 10**scale (scale <= 0); render as an exact decimal string
    if scale >= 0:
        return str(n * (10 ** scale))
    digits = "%0*d" % (-scale + 1, abs(n))
    return ("-" if n < 0 else "") + digits[:scale] + "." + digits[scale:]

_EPOCH_DAYS = datetime.date(1858, 11, 17).toordinal()

def _decode_date(raw):
    return datetime.date.fromordinal(_EPOCH_DAYS + struct.unpack("!i", raw)[0])

def _decode_time(raw):
    n = struct.unpack("!I", raw)[0]
    s, frac = divmod(n, 10000)
    return datetime.time(s // 3600, (s // 60) % 60, s % 60, frac * 100)

class _Column(object):
    __slots__ = ("name", "sqltype", "subtype", "scale", "length")

    def io_length(self):
        return self.length if self.sqltype == _SQL_TEXT else _SQL_TYPE_LENGTH[self.sqltype]

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
    def __init__(self, wire, filename, user, password):
        self._wire = wire
        self._filename = filename
        self._user = user
        self._password = password
        self._db_handle = None
        self._trans_handle = None

    def cursor(self):
        return Cursor(self)

    def commit(self):
        if self._trans_handle is not None:
            self._send(_pack_int(_op_commit_retaining) + _pack_int(self._trans_handle))
            self._response()

    def rollback(self):
        if self._trans_handle is not None:
            self._send(_pack_int(_op_rollback_retaining) + _pack_int(self._trans_handle))
            self._response()

    def close(self):
        try:
            if self._db_handle is not None:
                self._send(_pack_int(_op_detach) + _pack_int(self._db_handle))
                self._response()
        except Exception:
            pass
        self._wire.close()

    # ---- wire helpers ----

    def _send(self, data):
        self._wire.send(data)

    def _response(self):
        op = self._wire.recv_int()
        while op == _op_dummy:
            op = self._wire.recv_int()
        if op != _op_response:
            raise OperationalError("unexpected Firebird operation %d" % op)
        return self._parse_response()

    def _parse_response(self):
        head = self._wire.recv(16)
        handle = struct.unpack("!i", head[:4])[0]
        object_id = head[4:12]
        buf = self._wire.recv(struct.unpack("!i", head[12:16])[0], align=True)
        self._check_status()
        return handle, object_id, buf

    def _check_status(self):
        gds, message = set(), ""
        n = self._wire.recv_int()
        while n != _isc_arg_end:
            if n == _isc_arg_gds:
                gds_code = self._wire.recv_int()
                if gds_code:
                    gds.add(gds_code)
            elif n == _isc_arg_number:
                message += " %d" % self._wire.recv_int()
            elif n in (_isc_arg_string, _isc_arg_interpreted, _isc_arg_sql_state):
                s = self._wire.recv(self._wire.recv_int(), align=True)
                if n != _isc_arg_sql_state:
                    message += " " + s.decode("utf-8", "replace")
            n = self._wire.recv_int()
        if gds:
            message = ("(remote) firebird error %s%s" % (sorted(gds), message)).strip()
            if gds & _GDS_INTEGRITY:
                raise IntegrityError(message)
            if gds & _GDS_DATA:
                raise DataError(message)
            if _GDS_WARNING not in gds:
                raise OperationalError(message)

    # ---- query ----

    def _query(self, query):
        try:
            return self._run(query)
        except (struct.error, IndexError, ValueError, KeyError) as ex:
            raise InterfaceError("malformed server response: %s" % ex)

    def _run(self, query):
        qbytes = query.encode("utf-8")
        self._send(_pack_int(_op_allocate_statement) + _pack_int(self._db_handle))
        stmt = self._response()[0]

        desc_items = bytes(bytearray([_isc_info_sql_stmt_type])) + _INFO_SQL_SELECT_DESCRIBE_VARS
        self._send(_pack_int(_op_prepare_statement) + _pack_int(self._trans_handle) + _pack_int(stmt) +
                   _pack_int(3) + _pack_bytes(qbytes) + _pack_bytes(desc_items) + _pack_int(1024))
        buf = self._response()[2]
        stmt_type, columns = self._parse_describe(stmt, buf)

        exec_msg = (_pack_int(_op_execute) + _pack_int(stmt) + _pack_int(self._trans_handle) +
                    _pack_bytes(b"") + _pack_int(0) + _pack_int(0) + _pack_int(0))
        self._send(exec_msg)
        self._response()

        description, rows = None, []
        if stmt_type == _isc_info_sql_stmt_select and columns:
            description = [(c.name, c.sqltype, None, None, None, None, None) for c in columns]
            rows = self._fetch(stmt, columns)
        self._send(_pack_int(_op_free_statement) + _pack_int(stmt) + _pack_int(_DSQL_drop))
        self._response()
        return description, rows

    def _parse_describe(self, stmt, buf):
        stmt_type, columns = None, []
        i = 0
        while i < len(buf):
            if bytearray(buf[i:i + 3]) == bytearray([_isc_info_sql_stmt_type, 4, 0]):
                stmt_type = _le(buf[i + 3:i + 7])
                i += 7
            elif bytearray(buf[i:i + 2]) == bytearray([_isc_info_sql_select, _isc_info_sql_describe_vars]):
                i += 2
                ln = _le(buf[i:i + 2]); i += 2
                count = _le(buf[i:i + ln]); i += ln
                columns = [_Column() for _ in range(count)]
                next_index = self._parse_items(buf[i:], columns)
                while next_index > 0:  # describe buffer truncated: request the remaining columns
                    self._send(_pack_int(_op_info_sql) + _pack_int(stmt) + _pack_int(0) + _pack_bytes(
                        bytes(bytearray([_isc_info_sql_sqlda_start, 2])) + struct.pack("<H", next_index) +
                        _INFO_SQL_SELECT_DESCRIBE_VARS) + _pack_int(1024))
                    more = self._response()[2]
                    ln = _le(more[2:4])
                    next_index = self._parse_items(more[4 + ln:], columns)
                break
            else:
                break
        return stmt_type, columns

    def _parse_items(self, buf, columns):
        index, i = 0, 0
        buf = bytearray(buf)
        while i < len(buf):
            item = buf[i]
            if item == _isc_info_end:
                break
            if item == _isc_info_truncated:
                return index  # continue from here in another round
            if item == _isc_info_sql_describe_end:
                i += 1
                continue
            ln = _le(buf[i + 1:i + 3])
            value = buf[i + 3:i + 3 + ln]
            if item == _isc_info_sql_sqlda_seq:
                index = _le(value)
            elif item == _isc_info_sql_type:
                columns[index - 1].sqltype = _le(value) & ~1
            elif item == _isc_info_sql_sub_type:
                columns[index - 1].subtype = _le(value)
            elif item == _isc_info_sql_scale:
                columns[index - 1].scale = _le_signed(value)
            elif item == _isc_info_sql_length:
                columns[index - 1].length = _le(value)
            elif item == _isc_info_sql_alias:
                columns[index - 1].name = value.decode("utf-8", "replace")
            elif item == _isc_info_sql_field and not getattr(columns[index - 1], "name", None):
                columns[index - 1].name = value.decode("utf-8", "replace")
            i += 3 + ln
        return -1

    def _calc_blr(self, columns):
        ln = len(columns) * 2
        blr = [5, 2, 4, 0, ln & 0xff, ln >> 8]
        for c in columns:
            t = c.sqltype
            if t == _SQL_VARYING:
                blr += [37, c.length & 0xff, c.length >> 8]
            elif t == _SQL_TEXT:
                blr += [14, c.length & 0xff, c.length >> 8]
            elif t == _SQL_LONG:
                blr += [8, c.scale]
            elif t == _SQL_SHORT:
                blr += [7, c.scale]
            elif t == _SQL_INT64:
                blr += [16, c.scale]
            elif t == _SQL_INT128:
                blr += [26, c.scale]
            else:
                blr += _SQL_TYPE_BLR[t]
            blr += [7, 0]
        blr += [255, 76]
        return bytes(bytearray((256 + b) if b < 0 else b for b in blr))

    def _fetch(self, stmt, columns):
        blr = self._calc_blr(columns)
        nbytes = (len(columns) + 7) // 8
        blob_cols = [i for i, c in enumerate(columns) if c.sqltype == _SQL_BLOB]
        rows = []
        more = True
        while more:
            self._send(_pack_int(_op_fetch) + _pack_int(stmt) + _pack_bytes(blr) + _pack_int(0) + _pack_int(400))
            op = self._wire.recv_int()
            while op == _op_dummy:
                op = self._wire.recv_int()
            if op != _op_fetch_response:
                if op == _op_response:
                    self._parse_response()
                raise OperationalError("unexpected Firebird operation %d during fetch" % op)
            status = self._wire.recv_int()
            count = self._wire.recv_int()
            while count:
                null_bitmap = _le(self._wire.recv(nbytes, align=True))
                row = []
                for i, col in enumerate(columns):
                    if null_bitmap & (1 << i):
                        row.append(None)
                        continue
                    io = col.io_length()
                    ln = self._wire.recv_int() if io < 0 else io
                    raw = self._wire.recv(ln, align=True)
                    # blob columns yield an 8-byte blob id; resolve AFTER the fetch batch is fully drained
                    # (a blob sub-request mid-batch would interleave with the still-streaming rows and desync)
                    row.append(raw if col.sqltype == _SQL_BLOB else self._decode(col, raw))
                rows.append(row)
                op = self._wire.recv_int()
                status = self._wire.recv_int()
                count = self._wire.recv_int()
            more = status != 100
        for i in blob_cols:
            for row in rows:
                if row[i] is not None:
                    row[i] = self._read_blob(row[i], columns[i].subtype)
        return [tuple(row) for row in rows]

    def _decode(self, col, raw):
        t = col.sqltype
        if t == _SQL_TEXT:
            return self._decode_text(raw, rstrip=True)
        if t == _SQL_VARYING:
            return self._decode_text(raw, rstrip=False)
        if t in (_SQL_SHORT, _SQL_LONG, _SQL_INT64, _SQL_INT128):
            n = _b2i_signed(raw)
            return _scaled(n, col.scale) if col.scale else str(n)
        if t == _SQL_FLOAT:
            return repr(struct.unpack("!f", raw)[0])
        if t == _SQL_DOUBLE:
            return repr(struct.unpack("!d", raw)[0])
        if t == _SQL_BOOLEAN:
            return "true" if bytearray(raw)[0] else "false"
        if t == _SQL_DATE:
            return "%s" % _decode_date(raw)
        if t == _SQL_TIME:
            return "%s" % _decode_time(raw)
        if t == _SQL_TIMESTAMP:
            return "%s %s" % (_decode_date(raw[:4]), _decode_time(raw[4:]))
        if t == _SQL_BLOB:
            return self._read_blob(raw, col.subtype)
        return raw  # unknown/decimal-float type -> raw bytes (sqlmap hex-encodes)

    def _decode_text(self, raw, rstrip):
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw  # OCTETS / binary text -> bytes (sqlmap hex-encodes)
        return s.rstrip(" ") if rstrip else s

    def _read_blob(self, blob_id, subtype):
        self._send(_pack_int(_op_open_blob2) + _pack_int(0) + _pack_int(self._trans_handle) + blob_id)
        blob_handle = self._response()[0]
        data = b""
        while True:
            self._send(_pack_int(_op_get_segment) + _pack_int(blob_handle) + _pack_int(1024) + _pack_int(0))
            seg_status, _, buf = self._response()
            buf = bytearray(buf)
            j = 0
            while j < len(buf):
                seg_len = _le(buf[j:j + 2])
                data += bytes(buf[j + 2:j + 2 + seg_len])
                j += 2 + seg_len
            if seg_status == 2:  # last segment
                break
        self._send(_pack_int(_op_close_blob) + _pack_int(blob_handle))
        self._response()
        if subtype == 1:
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data
        return data

def _uid(user, plugin, plugin_list, public_key, wire_crypt):
    def param(k, v):
        if k != _CNCT_specific_data:
            return bytes(bytearray([k, len(v)])) + v
        out, i = b"", 0
        while len(v) > 254:
            out += bytes(bytearray([k, 255, i])) + v[:254]
            v = v[254:]
            i += 1
        return out + bytes(bytearray([k, len(v) + 1, i])) + v

    try:
        os_user = os.environ.get("USER", "") or os.environ.get("USERNAME", "")
    except Exception:
        os_user = ""
    specific = _hex(_minbe(public_key))
    r = param(_CNCT_login, user.encode("utf-8"))
    r += param(_CNCT_plugin_name, plugin)
    r += param(_CNCT_plugin_list, plugin_list)
    r += param(_CNCT_specific_data, specific)
    r += param(_CNCT_client_crypt, b"\x01\x00\x00\x00" if wire_crypt else b"\x00\x00\x00\x00")
    r += param(_CNCT_user, os_user.encode("utf-8"))
    r += param(_CNCT_host, socket.gethostname().encode("utf-8", "replace"))
    r += param(_CNCT_user_verification, b"")
    return r

def _hex(b):
    return "".join("%02x" % c for c in bytearray(b)).encode("ascii")

# protocol version tuples (version, arch=Generic 1, min_type=0, max_type=batch_send 3, weight); max_type is
# deliberately capped at 3 (not lazy_send 5) so every operation gets an immediate response (no deferred handles)
_PROTOCOLS = ("0000000a00000001000000000000000300000002",
              "ffff800b00000001000000000000000300000004",
              "ffff800c00000001000000000000000300000006",
              "ffff800d00000001000000000000000300000008",
              "ffff800e0000000100000000000000030000000a",
              "ffff800f0000000100000000000000030000000c",
              "ffff80100000000100000000000000030000000e",
              "ffff801100000001000000000000000300000010")

def connect(host=None, port=3050, user=None, password=None, database=None, connect_timeout=None, **kwargs):
    user = user or "SYSDBA"
    password = password or ""
    filename = (database or "").encode("utf-8")
    plugin, plugin_list = b"Srp256", b"Srp256,Srp,Legacy_Auth"

    try:
        sock = socket.create_connection((host or "localhost", int(port or 3050)), timeout=connect_timeout)
        sock.settimeout(None)
    except (socket.error, socket.timeout) as ex:
        raise OperationalError("could not connect to '%s:%s' (%s)" % (host, port, ex))

    wire = _Wire(sock)
    try:
        public_key, private_key = _srp_client_seed()
        packet = (_pack_int(_op_connect) + _pack_int(_op_attach) + _pack_int(3) + _pack_int(1) +
                  _pack_bytes(filename) + _pack_int(len(_PROTOCOLS)) +
                  _pack_bytes(_uid(user, plugin, plugin_list, public_key, True)))
        for p in _PROTOCOLS:
            packet += _unhex(p)
        wire.send(packet)

        _authenticate(wire, user, password, public_key, private_key)
        connection = Connection(wire, filename, user, password)
        _attach(connection, wire, user)
    except (DatabaseError, InterfaceError):
        wire.close()
        raise
    except Exception as ex:
        wire.close()
        raise OperationalError("Firebird login failed (%s)" % ex)
    return connection

def _unhex(s):
    return bytes(bytearray(int(s[i:i + 2], 16) for i in range(0, len(s), 2)))

def _normalize_user(user):
    if len(user) >= 2 and user[0] == '"' and user[-1] == '"':
        return user[1:-1].replace('""', '"')
    return user.upper()

def _authenticate(wire, user, password, public_key, private_key):
    op = wire.recv_int()
    while op == _op_dummy:
        op = wire.recv_int()
    if op == _op_reject:
        raise OperationalError("Firebird connection rejected")
    if op == _op_response:
        Connection(wire, b"", user, password)._parse_response()  # will raise the server error
        raise OperationalError("Firebird connection rejected")

    wire.recv(12)  # accept block: protocol version / architecture / type (not needed once lazy-send is off)
    if op == _op_accept:
        return b""  # plaintext, no encryption negotiated

    data = wire.recv_bytes()
    plugin_name = wire.recv_bytes()
    wire.recv_int()          # is_authenticated
    wire.recv_bytes()        # keys
    if plugin_name not in (b"Srp256", b"Srp"):
        raise NotSupportedError("unsupported Firebird auth plugin %r" % plugin_name)
    if not data:
        raise OperationalError("Firebird server sent no SRP challenge")

    salt_len = _le(data[:2])
    salt = data[2:2 + salt_len]
    # the server sends B as a hex integer, dropping a leading zero nibble when its top nibble is 0 (odd-length
    # hex ~5% of the time) - parse it as an integer, which is length-agnostic (byte-pairing would corrupt it)
    server_public = int(data[4 + salt_len:].decode("ascii"), 16)
    hash_algo = hashlib.sha256 if plugin_name == b"Srp256" else hashlib.sha1
    proof, session_key = _srp_client_proof(_normalize_user(user).encode("utf-8"),
                                           password.encode("utf-8"), salt,
                                           public_key, server_public, private_key, hash_algo)

    wire.send(_pack_int(_op_cont_auth) + _pack_bytes(_hex(proof)) + _pack_bytes(plugin_name) +
              _pack_bytes(b"Srp256,Srp,Legacy_Auth") + _pack_bytes(b""))
    buf = _read_response(wire, user, password)

    enc_plugin, nonce = _guess_wire_crypt(buf)
    if not (enc_plugin and session_key):
        raise NotSupportedError("Firebird server did not offer a supported wire-crypt plugin")
    wire.send(_pack_int(_op_crypt) + _pack_bytes(enc_plugin) + _pack_bytes(b"Symmetric"))
    if enc_plugin in (b"ChaCha", b"ChaCha64"):
        k = hashlib.sha256(session_key).digest()
        wire.set_ciphers(_ChaCha20(k, nonce), _ChaCha20(k, nonce))
    elif enc_plugin == b"Arc4":
        wire.set_ciphers(_ARC4(session_key), _ARC4(session_key))
    else:
        raise NotSupportedError("unsupported Firebird wire-crypt plugin %r" % enc_plugin)
    _read_response(wire, user, password)  # first encrypted message
    return session_key

def _read_response(wire, user, password):
    # a bare op_response reader used during the login handshake (before a Connection exists)
    op = wire.recv_int()
    while op == _op_dummy:
        op = wire.recv_int()
    if op == _op_cont_auth:
        raise OperationalError("Firebird authentication failed")
    if op != _op_response:
        raise OperationalError("unexpected Firebird operation %d during login" % op)
    return Connection(wire, b"", user, password)._parse_response()[2]

def _attach(connection, wire, user):
    dpb = bytearray([_isc_dpb_version1])
    dpb += bytearray([_isc_dpb_lc_ctype, 4]) + bytearray(b"UTF8")
    ub = user.encode("utf-8")
    dpb += bytearray([_isc_dpb_user_name, len(ub)]) + bytearray(ub)
    dpb += bytearray([_isc_dpb_process_id, 4]) + bytearray(struct.pack("<i", os.getpid() & 0x7fffffff))
    name = b"sqlmap"
    dpb += bytearray([_isc_dpb_process_name, len(name)]) + bytearray(name)
    wire.send(_pack_int(_op_attach) + _pack_int(0) + _pack_bytes(connection._filename) + _pack_bytes(bytes(dpb)))
    connection._db_handle = connection._response()[0]

    tpb = bytes(bytearray([_isc_tpb_version3, _isc_tpb_write, _isc_tpb_wait,
                           _isc_tpb_read_committed, _isc_tpb_rec_version]))
    wire.send(_pack_int(_op_transaction) + _pack_int(connection._db_handle) + _pack_bytes(tpb))
    connection._trans_handle = connection._response()[0]
