#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Protocol-transcript coverage for the dependency-free wire clients in extra/dbwire: PostgreSQL SCRAM
server verification, MySQL capability negotiation, TDS framing and affected-row counts, Trino session
state, and the shared DB-API error/URL helpers.

Network-free - a fake socket replays a recorded server transcript, so a hostile or malformed peer can be
expressed exactly. These are the cases that are awkward to reach against a real server: a rogue server
that does not know the password, a peer that never terminates a message, a server missing a mandatory
capability.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import base64
import hashlib
import hmac
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import extra.dbwire as dbwire
from extra.dbwire import clickhouse as _clickhouse
from extra.dbwire import connection_lost
from extra.dbwire import cubrid as _cubrid
from extra.dbwire import firebird as _firebird
from extra.dbwire import http_origin
from extra.dbwire import monetdb as _monetdb
from extra.dbwire import mysql as _mysql
from extra.dbwire import postgres as _postgres
from extra.dbwire import presto as _presto
from extra.dbwire import recvn
from extra.dbwire import sybase as _sybase
from extra.dbwire import tds as _tds


class FakeSocket(object):
    """Replays `inbound` to the client and records everything the client writes."""

    def __init__(self, inbound=b""):
        self.inbound = bytearray(inbound)
        self.sent = bytearray()
        self.timeouts = []
        self.closed = False

    def feed(self, data):
        self.inbound.extend(data)

    def recv(self, count):
        if not self.inbound:
            return b""
        chunk = bytes(self.inbound[:count])
        del self.inbound[:count]
        return chunk

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, value):
        self.timeouts.append(value)

    def setsockopt(self, *_args):
        pass

    def close(self):
        self.closed = True


def _pg(mtype, payload):
    return mtype + struct.pack("!I", len(payload) + 4) + payload


def _scram_transcript(password, client_nonce_from, server_extra="SRV", forge_signature=False, error=None):
    """Builds an AuthenticationSASLContinue + SASLFinal pair the way a real server would."""

    salt = b"0123456789abcdef"
    iterations = 4096
    snonce = client_nonce_from + server_extra
    server_first = "r=%s,s=%s,i=%d" % (snonce, base64.b64encode(salt).decode("ascii"), iterations)
    if error is not None:
        final = "e=%s" % error
    else:
        salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        client_first_bare = "n=,r=%s" % client_nonce_from
        auth_message = "%s,%s,c=biws,r=%s" % (client_first_bare, server_first, snonce)
        server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        signature = hmac.new(server_key, auth_message.encode("ascii"), hashlib.sha256).digest()
        if forge_signature:
            signature = os.urandom(32)
        final = "v=%s" % base64.b64encode(signature).decode("ascii")
    return server_first, final


class PostgresScramTest(unittest.TestCase):
    """RFC 5802 requires the CLIENT to authenticate the server too. dbwire has no TLS underneath, so this
    verification is the only thing standing between a scan and a server that merely answers the port."""

    def _run(self, password="secret", **kwargs):
        sock = FakeSocket(_pg(b"R", struct.pack("!I", 10) + b"SCRAM-SHA-256\x00\x00"))

        def _feed_rest():
            sent = bytes(sock.sent)
            client_first = sent[sent.index(b"SCRAM-SHA-256\x00") + 18:].decode("ascii")
            nonce = [_[2:] for _ in client_first.split(",") if _.startswith("r=")][0]
            server_first, final = _scram_transcript(password, nonce, **kwargs)
            sock.feed(_pg(b"R", struct.pack("!I", 11) + server_first.encode("ascii")))
            sock.feed(_pg(b"R", struct.pack("!I", 12) + final.encode("ascii")))
            sock.feed(_pg(b"R", struct.pack("!I", 0)))

        original = sock.recv

        def recv(count):                # top up lazily, once the client has sent its client-first
            if not sock.inbound and b"SCRAM-SHA-256\x00" in bytes(sock.sent):
                _feed_rest()
            return original(count)

        sock.recv = recv
        return _postgres._authenticate(sock, "user", password)

    def test_valid_server_is_accepted(self):
        self._run()                     # returns on AuthenticationOk without raising

    def test_forged_server_signature_is_rejected(self):
        """A server that does not hold the credentials cannot produce ServerSignature."""
        try:
            self._run(forge_signature=True)
            self.fail("a forged server signature was accepted")
        except dbwire.OperationalError as ex:
            self.assertIn("signature", str(ex))

    def test_server_nonce_must_extend_the_client_nonce(self):
        """A server answering with a nonce of its own has not seen the client's - RFC 5802 5.1."""

        sock = FakeSocket(_pg(b"R", struct.pack("!I", 10) + b"SCRAM-SHA-256\x00\x00"))
        original = sock.recv

        def recv(count):
            if not sock.inbound and b"SCRAM-SHA-256\x00" in bytes(sock.sent):
                server_first, final = _scram_transcript("secret", "COMPLETELYUNRELATED")
                sock.feed(_pg(b"R", struct.pack("!I", 11) + server_first.encode("ascii")))
                sock.feed(_pg(b"R", struct.pack("!I", 12) + final.encode("ascii")))
            return original(count)

        sock.recv = recv
        try:
            _postgres._authenticate(sock, "user", "secret")
            self.fail("an unrelated server nonce was accepted")
        except dbwire.OperationalError as ex:
            self.assertIn("nonce", str(ex))

    def test_server_reported_error_is_surfaced(self):
        try:
            self._run(error="invalid-proof")
            self.fail("a SCRAM error was ignored")
        except dbwire.OperationalError as ex:
            self.assertIn("invalid-proof", str(ex))

    def test_low_iteration_count_is_rejected(self):
        """A tiny iteration count makes an offline attack on the captured exchange cheap."""

        sock = FakeSocket(_pg(b"R", struct.pack("!I", 10) + b"SCRAM-SHA-256\x00\x00"))
        original = sock.recv

        def recv(count):
            if not sock.inbound and b"SCRAM-SHA-256\x00" in bytes(sock.sent):
                sent = bytes(sock.sent)
                client_first = sent[sent.index(b"SCRAM-SHA-256\x00") + 18:].decode("ascii")
                nonce = [_[2:] for _ in client_first.split(",") if _.startswith("r=")][0]
                first = "r=%sSRV,s=%s,i=1" % (nonce, base64.b64encode(b"salt").decode("ascii"))
                sock.feed(_pg(b"R", struct.pack("!I", 11) + first.encode("ascii")))
            return original(count)

        sock.recv = recv
        self.assertRaises(dbwire.OperationalError, _postgres._authenticate, sock, "user", "secret")


def _mysql_handshake(server_caps):
    """The initial handshake packet of a server advertising `server_caps`."""

    payload = b"\x0a" + b"8.0.0-fake\x00" + struct.pack("<I", 1) + b"12345678" + b"\x00"
    payload += struct.pack("<H", server_caps & 0xffff)
    payload += b"\x21" + struct.pack("<H", 2)
    payload += struct.pack("<H", (server_caps >> 16) & 0xffff)
    payload += struct.pack("<B", 21) + (b"\x00" * 10) + b"123456789012\x00"
    payload += b"mysql_native_password\x00"
    return payload


class MysqlCapabilityTest(unittest.TestCase):
    def _connect_with(self, server_caps):
        """Drive the real handshake path with a fake server advertising `server_caps`."""

        payload = _mysql_handshake(server_caps)
        sock = FakeSocket(struct.pack("<I", len(payload))[:3] + b"\x00" + payload)
        self._last_sock = sock
        saved = socket.create_connection
        socket.create_connection = lambda *a, **k: sock
        try:
            _mysql.connect(host="h", port=3306, user="u", password="p", database=None, connect_timeout=1)
        finally:
            socket.create_connection = saved
        return sock

    def test_server_without_protocol_41_is_refused_cleanly(self):
        """Claiming a capability the server never advertised desynchronizes the handshake instead of
        failing; refuse up front."""

        try:
            self._connect_with(_mysql._CLIENT_SECURE_CONNECTION)
            self.fail("a pre-4.1 server was accepted")
        except dbwire.OperationalError as ex:
            self.assertIn("4.1 protocol", str(ex))

    def test_client_flags_never_exceed_the_server_capabilities(self):
        caps = (_mysql._CLIENT_PROTOCOL_41 | _mysql._CLIENT_SECURE_CONNECTION | _mysql._CLIENT_LONG_PASSWORD)
        try:
            sock = self._connect_with(caps)         # fake server sends nothing back -> auth read fails
        except dbwire.Error:
            sock = self._last_sock
        sent = bytes(sock.sent)
        self.assertTrue(sent, "client sent no handshake response")
        flags = struct.unpack("<I", sent[4:8])[0]
        self.assertEqual(flags & ~caps, 0, "client claimed capabilities the server did not advertise")
        self.assertTrue(flags & _mysql._CLIENT_PROTOCOL_41)
        self.assertFalse(flags & _mysql._CLIENT_PLUGIN_AUTH, "PLUGIN_AUTH was not advertised by the server")


def _mysql_packets(data):
    """Splits a recorded client byte stream into MySQL packet payloads."""

    out, off = [], 0
    while off + 4 <= len(data):
        length = struct.unpack("<I", data[off:off + 3] + b"\x00")[0]
        out.append(bytes(data[off + 4:off + 4 + length]))
        off += 4 + length
    return out


class MysqlConnectTranscriptTest(unittest.TestCase):
    """connect() has to keep the connect deadline armed until the login exchange is over, and the charset
    has to end up set - a swallowed 'SET NAMES' failure decodes every later row as utf-8 that never was."""

    _OK = b"\x00\x00\x00\x02\x00\x00\x00"
    _ERR = b"\xff" + struct.pack("<H", 1115) + b"#42000" + b"Unknown character set: 'utf8mb4'"

    def _packet(self, payload, seq=0):
        return struct.pack("<I", len(payload))[:3] + struct.pack("<B", seq) + payload

    def _connect(self, *replies):
        caps = (_mysql._CLIENT_PROTOCOL_41 | _mysql._CLIENT_SECURE_CONNECTION | _mysql._CLIENT_PLUGIN_AUTH)
        handshake = _mysql_handshake(caps)
        inbound = self._packet(handshake) + b"".join(self._packet(_, 2) for _ in replies)
        sock = FakeSocket(inbound)
        saved = socket.create_connection
        socket.create_connection = lambda *a, **k: sock
        try:
            connection = _mysql.connect(host="h", port=3306, user="u", password="p", database=None, connect_timeout=7)
        finally:
            socket.create_connection = saved
        return connection, sock

    def test_deadline_is_dropped_only_once_logged_in(self):
        _connection, sock = self._connect(self._OK, self._OK, self._OK)
        self.assertIsNone(sock.timeouts[-1], "connect deadline outlived the handshake")
        self.assertNotIn(None, sock.timeouts[:-1], "connect deadline was dropped before the handshake")

    def test_deadline_is_kept_when_the_server_goes_silent(self):
        """A peer that accepts the connection and then says nothing is alive as far as keepalive() is
        concerned - without a deadline the login read never returns."""

        try:
            self._connect()                 # nothing after the handshake packet
            self.fail("a silent server was accepted")
        except dbwire.Error:
            pass

    def test_charset_falls_back_when_utf8mb4_is_rejected(self):
        """Pre-5.5.3 servers have no utf8mb4."""

        _connection, sock = self._connect(self._OK, self._ERR, self._OK, self._OK)
        queries = [_[1:] for _ in _mysql_packets(sock.sent) if _[:1] == b"\x03"]
        self.assertEqual(queries[:2], [b"SET NAMES utf8mb4", b"SET NAMES utf8"])
        self.assertIn(b"SET autocommit=1", queries)

    def test_charset_fallback_is_not_sent_when_utf8mb4_is_accepted(self):
        _connection, sock = self._connect(self._OK, self._OK, self._OK)
        queries = [_[1:] for _ in _mysql_packets(sock.sent) if _[:1] == b"\x03"]
        self.assertEqual(queries, [b"SET NAMES utf8mb4", b"SET autocommit=1"])


class TdsFramingTest(unittest.TestCase):
    def _packet(self, body, eom=True):
        return struct.pack(">BBHHBB", 4, 1 if eom else 0, len(body) + 8, 0, 0, 0) + body

    def test_message_is_reassembled_across_packets(self):
        sock = FakeSocket(self._packet(b"AAA", eom=False) + self._packet(b"BBB", eom=True))
        self.assertEqual(_tds._read_message(sock), b"AAABBB")

    def test_unterminated_message_is_bounded(self):
        """The packet length is 16-bit, so a per-packet cap can never fire: a peer that never sets EOM
        would stream forever. The CUMULATIVE message is what must be bounded."""

        chunk = self._packet(b"A" * 4000, eom=False)
        sock = FakeSocket(chunk * 64)

        original = sock.recv

        def recv(count):                # endless stream of non-final packets
            if not sock.inbound:
                sock.feed(chunk * 64)
            return original(count)

        sock.recv = recv
        saved = _tds._MAX_MESSAGE_LENGTH
        try:
            _tds._MAX_MESSAGE_LENGTH = 100000
            self.assertRaises(dbwire.InterfaceError, _tds._read_message, sock)
        finally:
            _tds._MAX_MESSAGE_LENGTH = saved

    def test_zero_length_packet_is_rejected(self):
        sock = FakeSocket(struct.pack(">BBHHBB", 4, 1, 0, 0, 0, 0))
        self.assertRaises(dbwire.InterfaceError, _tds._read_message, sock)

    def test_done_token_carries_the_affected_row_count(self):
        """DONE reports DoneRowCount when the DONE_COUNT status bit is set - the only place a DML
        statement's affected-row count exists, since it returns no rows."""

        done = struct.pack("<B", 0xfd) + struct.pack("<HHq", _tds._DONE_COUNT, 0, 5000)
        sock = FakeSocket(struct.pack(">BBHHBB", 4, 1, len(done) + 8, 0, 0, 0) + done)
        description, rows, affected = _tds._parse_tokens(sock)
        self.assertIsNone(description)
        self.assertEqual(rows, [])
        self.assertEqual(affected, 5000)

    def test_done_without_the_count_flag_is_not_a_row_count(self):
        done = struct.pack("<B", 0xfd) + struct.pack("<HHq", 0, 0, 1234)
        sock = FakeSocket(struct.pack(">BBHHBB", 4, 1, len(done) + 8, 0, 0, 0) + done)
        self.assertIsNone(_tds._parse_tokens(sock)[2])


class SybaseLoginTest(unittest.TestCase):
    """The TDS 5.0 LOGINREC is one fixed-layout record: every field sits at a byte offset the server counts
    on, so a field that changes width silently shifts the credentials into the reserved area."""

    def _loginrec(self):
        return _sybase._loginrec("dbwire", "tester", "guest1234", "dbwire", "srv", "utf8", 2048)

    def test_field_offsets_match_the_fixed_layout(self):
        login = self._loginrec()
        self.assertEqual(len(login), 568 + 35, "LOGINREC is not the fixed 568 bytes plus a CAPABILITY token")
        for offset, size, expected in ((0, 30, b"dbwire"), (31, 30, b"tester"), (62, 30, b"guest1234"),
                                       (140, 30, b"dbwire"), (171, 30, b"srv"), (462, 10, b"dbwire"),
                                       (525, 30, b"utf8"), (557, 6, b"2048")):
            self.assertEqual(login[offset:offset + size].rstrip(b"\x00"), expected, offset)
            self.assertEqual(login[offset + size:offset + size + 1], struct.pack("<B", len(expected)), offset)
        self.assertEqual(login[458:462], b"\x05\x00\x00\x00", "TDS version is not 5.0.0.0")
        self.assertEqual(login[202:204], b"\x00\x09", "remote password is not prefixed with its length")
        self.assertEqual(login[457:458], struct.pack("<B", 11), "remote password length excludes the prefix")

    def test_no_optional_capability_is_claimed(self):
        """A claimed capability makes the server answer in that format. Everything this client cannot parse
        - wide ROWFMT2 rows above all - has to stay unclaimed, so the server converts down to the baseline."""

        capability = self._loginrec()[568:]
        self.assertEqual(bytearray(capability)[0], 0xe2)
        self.assertEqual(capability[3:5], b"\x01\x0e")           # request capabilities, 14 bytes
        self.assertEqual(capability[5:19], b"\x00" * 14)
        self.assertEqual(capability[19:21], b"\x02\x0e")         # response capabilities, 14 bytes
        self.assertEqual(capability[21:35], b"\x00" * 14)


class SybaseTokenTest(unittest.TestCase):
    """Fixtures are bytes recorded off ASE 16's wire."""

    def _response(self, blob):
        class Replay(object):
            def __init__(self, data):
                self.data = bytearray(data)

            def recv(self, count):
                chunk = bytes(self.data[:count]); del self.data[:count]; return chunk

        packet = struct.pack(">BBHHBB", 4, 1, len(blob) + 8, 0, 0, 0) + blob
        return _sybase.Connection(Replay(packet), "utf-8")._read_response()

    def test_rowfmt_and_row(self):
        blob = (b"\xee\x19\x00\x02\x00\x03one\x10\x07\x00\x00\x00\x38\x00"
                b"\x03txt\x10\x02\x00\x00\x00\x27\x03\x00"
                b"\xd1\x01\x00\x00\x00\x03abc"
                b"\xfd\x10\x00\x02\x00\x01\x00\x00\x00")
        description, rows, affected = self._response(blob)
        self.assertEqual([_[0] for _ in description], ["one", "txt"])
        self.assertEqual(rows, [("1", "abc")])
        self.assertEqual(affected, 1)

    def test_done_row_count_is_four_bytes(self):
        """Microsoft widened DoneRowCount to 8 bytes; ASE did not, so reading 8 here eats the next token."""

        description, rows, affected = self._response(b"\xfd\x10\x00\x02\x00\x2a\x00\x00\x00")
        self.assertIsNone(description)
        self.assertEqual(affected, 42)
        self.assertIsNone(self._response(b"\xfd\x00\x00\x02\x00\x2a\x00\x00\x00")[2],
                          "a row count without the DONE_COUNT status bit is meaningless")

    def test_server_error_is_raised_and_informational_message_is_not(self):
        def eed(number, severity, message):
            body = (struct.pack("<i", number) + struct.pack("<3B", 1, severity, 5) + b"ZZZZZ" +
                    b"\x00" + struct.pack("<H", 1) + struct.pack("<H", len(message)) + message +
                    struct.pack("<B", 8) + b"MYSYBASE" + b"\x00" + struct.pack("<H", 1))
            return b"\xe5" + struct.pack("<H", len(body)) + body

        # severity 10 and below is informational - 'Changed database context' arrives on every USE
        self._response(eed(5701, 10, b"Changed database context to 'master'.") +
                       b"\xfd\x00\x00\x02\x00\x00\x00\x00\x00")
        fatal = eed(208, 16, b"nope not found. Specify owner.objectname")
        try:
            self._response(fatal + b"\xfd\x02\x00\x02\x00\x00\x00\x00\x00")
            self.fail("a severity 16 server error was swallowed")
        except dbwire.ProgrammingError as ex:
            self.assertIn("not found", str(ex))

    def test_packet_size_negotiation_is_honoured(self):
        """A packet bigger than the login negotiated is not refused, the connection is dropped - so the
        server's answer to the requested size has to become the send chunk size."""

        envchange = b"\xe3\x07\x00\x04\x04" + b"8192" + b"\x00"
        class Replay(object):
            def __init__(self, data):
                self.data = bytearray(data)

            def recv(self, count):
                chunk = bytes(self.data[:count]); del self.data[:count]; return chunk

        blob = envchange + b"\xfd\x00\x00\x02\x00\x00\x00\x00\x00"
        connection = _sybase.Connection(Replay(struct.pack(">BBHHBB", 4, 1, len(blob) + 8, 0, 0, 0) + blob), "utf-8")
        self.assertEqual(connection._chunk, _sybase._PACKET_SIZE - 8)
        connection._read_response()
        self.assertEqual(connection._chunk, 8192 - 8)


class SybaseDecoderTest(unittest.TestCase):
    def _column(self, dtype, scale=0, usertype=0):
        col = _sybase._Column()
        col.name, col.type, col.size, col.scale, col.usertype = "c", dtype, 0, scale, usertype
        return col

    def test_numeric_is_the_mirror_image_of_the_microsoft_encoding(self):
        """ASE sends a big-endian magnitude with 1 meaning negative; Microsoft sends little-endian with 1
        meaning positive. Sharing one decoder between the two silently returns wrong numbers."""

        for raw, scale, expected in ((b"\x01\x00\x00\xbcaN", 3, "-12345.678"),
                                     (b"\x00\x00\x00'\x0f", 2, "99.99"),
                                     (b"\x00\x00\x00\x00\x01", 0, "1"),
                                     (b"\x01\x00\x00\x00\x01", 0, "-1")):
            self.assertEqual(_sybase._decode_numeric(raw, scale), expected, raw)
        self.assertNotEqual(_sybase._decode_numeric(b"\x01\x00\x00\xbcaN", 3),
                            _tds._decode_numeric(b"\x01\x00\x00\xbcaN", 3))

    def test_date_and_time_columns_survive_the_servers_conversion(self):
        """Unclaimed date/time capabilities make ASE send both as a plain datetime; only the user type still
        says how much of it the column holds."""

        raw = struct.pack("<iI", 46245, 0)
        self.assertEqual(_sybase._decode_value(self._column(0x6f, usertype=37), raw, "utf-8"), "2026-08-13")
        raw = struct.pack("<iI", 0, 11001600)
        self.assertEqual(_sybase._decode_value(self._column(0x6f, usertype=38), raw, "utf-8"), "10:11:12")
        raw = struct.pack("<iI", 46245, 11001704)
        self.assertTrue(_sybase._decode_value(self._column(0x6f), raw, "utf-8").startswith("2026-08-13 10:11:12"))

    def test_unicode_columns_are_told_apart_by_user_type(self):
        """univarchar travels as LONGBINARY: without the user type it would be hex-dumped as binary."""

        raw = u"\u017eabac".encode("utf-16-le")
        self.assertEqual(_sybase._decode_value(self._column(0xe1, usertype=35), raw, "utf-8"), u"\u017eabac")
        self.assertEqual(_sybase._decode_value(self._column(0xe1), raw, "utf-8"), raw)

    def test_integers_and_money(self):
        self.assertEqual(_sybase._decode_value(self._column(0x26), b"\xc8", "utf-8"), "200")   # tinyint
        self.assertEqual(_sybase._decode_value(self._column(0x26), b"\xf9\xff", "utf-8"), "-7")
        self.assertEqual(_sybase._decode_value(self._column(0x26), b"\xff" * 7 + b"\x7f", "utf-8"),
                         "9223372036854775807")
        self.assertEqual(_sybase._decode_value(self._column(0x6e), b"\x00\x00\x00\x00\x40\xe2\x01\x00", "utf-8"),
                         "12.3456")

    def test_a_zero_length_value_is_null(self):
        """TDS 5 has no separate NULL marker for a length-prefixed value - and neither has ASE."""

        col = self._column(0x27)
        self.assertIsNone(_sybase._read_value(col, b"\x00", 0, "utf-8")[0])
        self.assertEqual(_sybase._read_value(col, b"\x03abc", 0, "utf-8")[0], "abc")


class TrinoSessionStateTest(unittest.TestCase):
    """Trino is stateless on the wire: the server reports each session change as a response header and the
    client must echo it back, or USE / SET SESSION silently do nothing on the next statement."""

    def _connection(self):
        return _presto.Connection("h", 8080, "u", None, "tpch", "tiny", 10)

    def test_set_catalog_and_schema_are_carried(self):
        c = self._connection()
        c._apply_state({"x-trino-set-catalog": "hive", "x-trino-set-schema": "sf1"})
        self.assertEqual(c._headers["X-Trino-Catalog"], "hive")
        self.assertEqual(c._headers["X-Trino-Schema"], "sf1")

    def test_session_properties_accumulate_and_clear(self):
        c = self._connection()
        c._apply_state({"x-trino-set-session": "query_max_run_time=7m"})
        self.assertEqual(c._headers["X-Trino-Session"], "query_max_run_time=7m")
        c._apply_state({"x-trino-set-session": "join_distribution_type=BROADCAST"})
        self.assertIn("join_distribution_type=BROADCAST", c._headers["X-Trino-Session"])
        self.assertIn("query_max_run_time=7m", c._headers["X-Trino-Session"])
        c._apply_state({"x-trino-clear-session": "query_max_run_time"})
        self.assertNotIn("query_max_run_time", c._headers["X-Trino-Session"])

    def test_transaction_id_is_carried_then_cleared(self):
        c = self._connection()
        c._apply_state({"x-trino-started-transaction-id": "abc123"})
        self.assertEqual(c._headers["X-Trino-Transaction-Id"], "abc123")
        c._apply_state({"x-trino-clear-transaction-id": "true"})
        self.assertNotIn("X-Trino-Transaction-Id", c._headers)

    def test_schema_is_never_sent_without_a_catalog(self):
        """Trino rejects every request with 'Schema is set but catalog is not'."""

        c = _presto.Connection("h", 8080, "u", None, None, "tiny", 10)
        self.assertNotIn("X-Trino-Schema", c._headers)
        self.assertNotIn("X-Presto-Schema", c._headers)


class CubridAutoCommitTest(unittest.TestCase):
    """CUBRID has no server-side autocommit switch that outlives a statement: the EXECUTE request carries
    its own auto_commit byte, and a statement sent with it clear is rolled back when the CAS worker goes
    away. It must stay clear for a SELECT, whose request handle the paged fetch still reads from."""

    def _auto_commit_byte(self, stmt_type):
        connection = object.__new__(_cubrid.Connection)
        connection._protocol_version = 8
        connection._sock = None
        sent = []

        def _call(writer):
            sent.append(writer.payload())
            # EXECUTE response: total(4) cache_reusable(1) result_count(4) includes_column_info(1) shard_id(4)
            return _cubrid._Reader(struct.pack(">iBiBi", 0, 0, 0, 0, 0))

        connection._call = _call
        prepare = _cubrid._Reader(struct.pack(">iBiBi", 0, stmt_type, 0, 0, 0))
        connection._execute(1, prepare)

        args, off = [], 1                       # skip the function code, then walk [len(4)][value] args
        payload = sent[0]
        while off < len(payload):
            (length,) = struct.unpack(">i", payload[off:off + 4])
            args.append(payload[off + 4:off + 4 + length])
            off += 4 + length
        return bytearray(args[6])[0]            # handle, flag, max_col_size, max_row, binds, fetch, auto_commit

    def test_dml_is_committed_by_the_execute_request(self):
        self.assertEqual(self._auto_commit_byte(_cubrid._STMT_SELECT + 1), 1)

    def test_select_does_not_end_the_transaction(self):
        self.assertEqual(self._auto_commit_byte(_cubrid._STMT_SELECT), 0)


class BoundedReadTest(unittest.TestCase):
    """A length taken off the wire is attacker/corruption controlled: unchecked, it either reads until
    memory runs out or (on a short buffer) hands back silently truncated data."""

    def test_cubrid_short_response_is_not_silently_truncated(self):
        reader = _cubrid._Reader(b"AB")
        self.assertRaises(dbwire.InterfaceError, reader.raw, 8)
        self.assertRaises(dbwire.InterfaceError, reader.raw, -1)

    def test_firebird_rejects_an_out_of_range_length(self):
        wire = _firebird._Wire(FakeSocket())
        self.assertRaises(dbwire.InterfaceError, wire.recv, -1)
        self.assertRaises(dbwire.InterfaceError, wire.recv, _firebird._MAX_MESSAGE_LENGTH + 1)

    def test_monetdb_unterminated_block_stream_is_bounded(self):
        """The MAPI block length is a 15-bit field, so only the accumulated response can be bounded."""

        block = struct.pack("<H", (4000 << 1) | 0) + b"A" * 4000       # last-flag clear -> never ends
        sock = FakeSocket(block * 32)
        original = sock.recv

        def recv(count):
            if not sock.inbound:
                sock.feed(block * 32)
            return original(count)

        sock.recv = recv
        saved = _monetdb._MAX_MESSAGE_LENGTH
        try:
            _monetdb._MAX_MESSAGE_LENGTH = 100000
            self.assertRaises(dbwire.InterfaceError, _monetdb._getblock, sock)
        finally:
            _monetdb._MAX_MESSAGE_LENGTH = saved


class DecoderTest(unittest.TestCase):
    """Byte fixtures for the socket-free decoders, taken from what the real servers put on the wire."""

    def test_tds_column_name_is_a_character_count(self):
        """COLMETADATA ColName is B_VARCHAR - a length in UCS-2 characters (MS-TDS 2.2.7.4), so the count
        byte is followed by twice as many bytes."""

        data = struct.pack("<B", 3) + u"abc".encode("utf-16-le") + b"TRAILING"
        self.assertEqual(_tds._read_b_varchar(data, 0), ("abc", 7))
        self.assertEqual(_tds._read_b_varchar(struct.pack("<B", 0) + b"X", 0), ("", 1))

    def test_clickhouse_tabseparated_escapes(self):
        """ClickHouse escapes only \\t \\n \\r \\0 \\b \\f \\' \\\\ - a control byte such as 0x01 is written
        raw, and a String holding invalid UTF-8 comes back as bytes rather than mojibake."""

        self.assertIsNone(_clickhouse._unescape(b"\\N"))
        self.assertEqual(_clickhouse._unescape(b"tab\\there"), b"tab\there")
        self.assertEqual(_clickhouse._unescape(b"nl\\nx"), b"nl\nx")
        self.assertEqual(_clickhouse._unescape(b"a\\\\b"), b"a\\b")
        self.assertEqual(_clickhouse._unescape(b"\\0"), b"\x00")
        self.assertEqual(_clickhouse._unescape(b"\x01\x02"), b"\x01\x02")
        self.assertEqual(_clickhouse._decode_cell(b"\x00\xff\x80"), b"\x00\xff\x80")

    def test_postgres_bytea_both_output_formats(self):
        """bytea arrives as text in whatever bytea_output the server is set to. 'escape' renders a literal
        backslash as '\\\\', so it can never collide with the '\\x' hex-format prefix."""

        for wire, expected in ((b"\\x5c78414243", b"\\xABC"),   # hex format
                               (b"\\\\xABC", b"\\xABC"),        # escape format, value starts with a backslash
                               (b"\\x00ff80", b"\x00\xff\x80"),
                               (b"\\000\\377\\200", b"\x00\xff\x80"),
                               (b"\\\\", b"\\"),
                               (b"\\\\001", b"\\001")):
            self.assertEqual(_postgres._decode_bytea(wire), expected, wire)

    def test_monetdb_quoted_values_keep_the_delimiter_out(self):
        """mserver escapes tab/quote/newline/backslash INSIDE a quoted value, so the literal ',\\t' field
        delimiter cannot occur in one; control bytes arrive as C octal escapes."""

        line = u'[ 2,\t"a,\\tb",\t"q\\"uote",\t"ctl:\\001",\t"euro-\u20ac",\tNULL\t]'
        description, rows = _monetdb._parse_result(u"%% id,\tv # name\n%s" % line)
        self.assertEqual([_[0] for _ in description], ["id", "v"])
        self.assertEqual(rows, [("2", "a,\tb", 'q"uote', "ctl:\x01", u"euro-\u20ac", None)])

    def test_cubrid_error_classification(self):
        """CUBRID points at the offending token as "before '<fragment>'"; a coercion failure is a DataError."""

        for message, expected in (("(remote) Syntax: In line 1, column 1 before ' 1'", dbwire.ProgrammingError),
                                  ("(remote) Unknown class \"public.t\".", dbwire.ProgrammingError),
                                  ("(remote) Cannot coerce value of domain \"character\" to domain \"integer\".",
                                   dbwire.DataError),
                                  ("(remote) unique constraint violated", dbwire.IntegrityError)):
            self.assertRaises(expected, _cubrid.Connection._raise, -494, message)


class HelperTest(unittest.TestCase):
    def test_socket_failure_maps_into_the_dbapi_hierarchy(self):
        """Callers of a PEP 249 driver only catch Error and its subclasses."""

        self.assertIsInstance(connection_lost(socket.error("boom")), dbwire.OperationalError)
        self.assertIsInstance(connection_lost(socket.error("boom")), dbwire.Error)

    def test_http_origin_brackets_a_literal_ipv6_host(self):
        self.assertEqual(http_origin("10.0.0.5", 8123), "http://10.0.0.5:8123")
        self.assertEqual(http_origin("::1", 8123), "http://[::1]:8123")
        self.assertEqual(http_origin("[fe80::1]", 8123), "http://[fe80::1]:8123")
        self.assertEqual(http_origin(None, 8123), "http://localhost:8123")

    def test_recvn_reads_exactly_n_bytes_across_chunks(self):
        """Shared by every socket module: a framed protocol has no notion of a short read."""

        sock = FakeSocket(b"ABCDEFGH")
        original = sock.recv
        sock.recv = lambda _count: original(3)          # dribble the stream 3 bytes at a time
        self.assertEqual(recvn(sock, 8), b"ABCDEFGH")
        self.assertRaises(dbwire.InterfaceError, recvn, FakeSocket(b"AB"), 4)

    def test_every_module_exposes_the_dbapi_surface(self):
        for name in ("postgres", "mysql", "tds", "sybase", "firebird", "cubrid", "monetdb", "clickhouse", "presto"):
            module = __import__("extra.dbwire.%s" % name, fromlist=["connect"])
            self.assertTrue(callable(getattr(module, "connect", None)), name)


if __name__ == "__main__":
    unittest.main()
