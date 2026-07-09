#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit coverage for the PURE (network-free) parts of the native WebSocket client in
lib/request/websocket.py: the RFC 6455 accept-key computation, client frame masking,
the length-encoding boundaries (7/16/64-bit), fragment reassembly and control-frame
handling. No socket is opened - frames are fed through a primed buffer and a fake sink.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import base64
import hashlib
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.request.websocket import (
    WebSocket,
    WebSocketConnectionClosedException,
    WebSocketTimeoutException,
    _GUID,
    OPCODE_TEXT,
    OPCODE_CONTINUATION,
    OPCODE_PING,
    OPCODE_CLOSE,
)


class _FakeSock(object):
    """Captures everything the client sends, so masked client frames / PONGs can be inspected."""
    def __init__(self):
        self.sent = b""

    def sendall(self, data):
        self.sent += data

    def close(self):
        pass


def _serverFrame(data, opcode=OPCODE_TEXT, fin=1):
    """Build an (unmasked, server->client) frame carrying data."""
    if not isinstance(data, bytes):
        data = data.encode("utf-8")
    frame = bytearray([(fin << 7) | opcode])
    length = len(data)
    if length < 126:
        frame.append(length)
    elif length < 65536:
        frame.append(126); frame += struct.pack("!H", length)
    else:
        frame.append(127); frame += struct.pack("!Q", length)
    frame += data
    return bytes(frame)


def _client(buffer=b""):
    ws = WebSocket.__new__(WebSocket)   # bypass connect(): no socket
    ws.sock = _FakeSock()
    ws.status = 101
    ws._headers = {}
    ws._timeout = None
    ws._buffer = buffer
    ws._closed = False
    return ws


class TestWebSocket(unittest.TestCase):
    def test_accept_key_rfc6455_vector(self):
        # RFC 6455 section 1.3 canonical example
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        accept = base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")
        self.assertEqual(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_client_frame_is_masked_and_roundtrips(self):
        ws = _client()
        ws._sendFrame(b"hello", OPCODE_TEXT)
        raw = ws.sock.sent
        self.assertEqual(bytearray(raw)[0], 0x80 | OPCODE_TEXT)   # FIN + text
        self.assertTrue(bytearray(raw)[1] & 0x80, "client frame must set the mask bit")

        # feeding the client's own (masked) frame back through the parser must recover the payload
        fin, opcode, payload = _client(raw)._recvFrame()
        self.assertEqual((fin, opcode, bytes(payload)), (1, OPCODE_TEXT, b"hello"))

    def test_length_encoding_boundaries(self):
        for size in (125, 126, 65535, 65536):
            ws = _client()
            ws._sendFrame(b"A" * size, OPCODE_TEXT)
            fin, opcode, payload = _client(ws.sock.sent)._recvFrame()
            self.assertEqual(len(payload), size, msg="round-trip failed at length %d" % size)

    def test_recv_reassembles_fragments(self):
        buf = _serverFrame("ab", OPCODE_TEXT, fin=0) + _serverFrame("cd", OPCODE_CONTINUATION, fin=1)
        self.assertEqual(_client(buf).recv(), "abcd")

    def test_recv_answers_ping_then_returns_data(self):
        ws = _client(_serverFrame("hi", OPCODE_PING) + _serverFrame("data", OPCODE_TEXT))
        self.assertEqual(ws.recv(), "data")
        # a PONG (opcode 0xA) carrying the ping payload must have been sent back
        pong = bytearray(ws.sock.sent)
        self.assertEqual(pong[0], 0x80 | 0xA)

    def test_recv_close_raises(self):
        ws = _client(_serverFrame(struct.pack("!H", 1000), OPCODE_CLOSE))
        self.assertRaises(WebSocketConnectionClosedException, ws.recv)

    def test_read_timeout_maps_to_ws_timeout(self):
        import socket as _socket
        import ssl as _ssl

        class _RaisingSock(object):
            def __init__(self, exc):
                self.exc = exc
            def recv(self, n):
                raise self.exc

        # both a plain socket timeout and Python 2's TLS 'read operation timed out' must surface as
        # WebSocketTimeoutException (sqlmap's frame loop relies on it), while other SSL errors propagate
        for exc in (_socket.timeout("timed out"), _ssl.SSLError("The read operation timed out")):
            ws = _client(); ws.sock = _RaisingSock(exc)
            self.assertRaises(WebSocketTimeoutException, ws.recv)

        ws = _client(); ws.sock = _RaisingSock(_ssl.SSLError("decryption failed"))
        self.assertRaises(_ssl.SSLError, ws.recv)


if __name__ == "__main__":
    unittest.main()
