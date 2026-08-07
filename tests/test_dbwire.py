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
from extra.dbwire import connection_lost
from extra.dbwire import http_origin
from extra.dbwire import mysql as _mysql
from extra.dbwire import postgres as _postgres
from extra.dbwire import presto as _presto
from extra.dbwire import tds as _tds


class FakeSocket(object):
    """Replays `inbound` to the client and records everything the client writes."""

    def __init__(self, inbound=b""):
        self.inbound = bytearray(inbound)
        self.sent = bytearray()
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

    def settimeout(self, _value):
        pass

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


class MysqlCapabilityTest(unittest.TestCase):
    def _handshake(self, server_caps):
        payload = b"\x0a" + b"8.0.0-fake\x00" + struct.pack("<I", 1) + b"12345678" + b"\x00"
        payload += struct.pack("<H", server_caps & 0xffff)
        payload += b"\x21" + struct.pack("<H", 2)
        payload += struct.pack("<H", (server_caps >> 16) & 0xffff)
        payload += struct.pack("<B", 21) + (b"\x00" * 10) + b"123456789012\x00"
        payload += b"mysql_native_password\x00"
        return payload

    def _connect_with(self, server_caps):
        """Drive the real handshake path with a fake server advertising `server_caps`."""

        payload = self._handshake(server_caps)
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

    def test_every_module_exposes_the_dbapi_surface(self):
        for name in ("postgres", "mysql", "tds", "firebird", "cubrid", "monetdb", "clickhouse", "presto"):
            module = __import__("extra.dbwire.%s" % name, fromlist=["connect"])
            self.assertTrue(callable(getattr(module, "connect", None)), name)


if __name__ == "__main__":
    unittest.main()
