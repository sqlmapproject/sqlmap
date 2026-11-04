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
from lib.request.connect import Connect

_GET_PAGE = Connect.__dict__["getPage"]


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

    def test_handshake_host_port(self):
        # Note: only the scheme's own default port is omitted (port 443 used to be dropped for 'ws://' too)
        import lib.request.websocket as W

        class _Sent(Exception):
            pass

        class _Capture(_FakeSock):
            def settimeout(self, value):
                pass

            def sendall(self, data):
                raise _Sent(data)

        original = W.socket.create_connection
        try:
            W.socket.create_connection = lambda *args, **kwargs: _Capture()
            for url, host in (("ws://example.com:443/x", "example.com:443"), ("ws://example.com:80/x", "example.com"), ("ws://example.com:8080/x", "example.com:8080")):
                ws = WebSocket.__new__(WebSocket)
                ws._timeout = None
                try:
                    ws.connect(url)
                except _Sent as ex:
                    self.assertIn(("Host: %s\r\n" % host).encode(), ex.args[0])
                else:
                    self.fail("handshake was not sent")
        finally:
            W.socket.create_connection = original

    def test_getpage_preserves_host_header(self):
        import socket
        import tempfile
        import lib.request.websocket as W
        from lib.core.data import conf, kb
        from lib.core.option import _setKnowledgeBaseAttributes
        from lib.core.threads import getCurrentThreadData

        class _HandshakeSock(_FakeSock):
            def __init__(self):
                _FakeSock.__init__(self)
                self.handshake = None
                self.response = b""

            def settimeout(self, value):
                pass

            def sendall(self, data):
                if self.handshake is None:
                    self.handshake = data
                    key = next(line.split(b":", 1)[1].strip() for line in data.split(b"\r\n") if line.lower().startswith(b"sec-websocket-key:"))
                    accept = base64.b64encode(hashlib.sha1(key + _GUID.encode("ascii")).digest())
                    self.response = b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n" + _serverFrame("ok")

            def recv(self, size):
                result, self.response = self.response[:size], self.response[size:]
                return result

        sockets = []
        def create_socket(*args, **kwargs):
            sock = _HandshakeSock()
            sockets.append(sock)
            return sock

        oldConf, oldKb = dict(conf), dict(kb)
        threadData = getCurrentThreadData()
        oldThreadData = dict(threadData.__dict__)
        oldTimeout = socket.getdefaulttimeout()
        original = W.socket.create_connection
        oldGetPage = Connect.__dict__["getPage"]
        fd, headersFile = tempfile.mkstemp(prefix="sqlmap-ws-headers-")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("hOsT: file.example\n")
            threadData.__dict__.clear()
            threadData.reset()
            _setKnowledgeBaseAttributes(False)
            kb.wizardMode, kb.webSocketRecvCount = True, 1
            conf.url = "ws://example.test:8080/test"
            conf.hostname, conf.scheme, conf.port, conf.path = "example.test", "ws", 8080, "/test"
            conf.parameters, conf.data = {}, None
            conf.abortCode, conf.ignoreCode = [], []
            conf.timeout, conf.batch, conf.keepAlive = 3, True, False
            conf.retryOn, conf.ignoreRedirects, conf.scope = None, False, None
            W.socket.create_connection = create_socket
            Connect.getPage = _GET_PAGE
            cases = (
                ("ws://example.test:8080/test", [], None, None, None, False, "example.test:8080"),
                ("ws://user:pass@example.test:8080/test", [], None, None, None, False, "example.test:8080"),
                ("ws://example.test:8080/test", [('hOsT', 'configured.example')], None, None, None, False, "configured.example"),
                ("ws://example.test:8080/test", [('Host', 'configured.example')], "override.example:8443", None, None, False, "override.example:8443"),
                ("ws://example.test:8080/test", [], None, {'Host': 'aux.example'}, None, False, "aux.example"),
                ("ws://example.test:8080/test", [], None, None, headersFile, False, "file.example"),
                ("ws://example.test:8080/test", [], None, None, None, True, "localhost"),
            )
            for url, headers, host, aux, path, localhost, expected in cases:
                conf.url = url
                conf.httpHeaders = headers
                conf.localhost, kb.headersFile = localhost, path
                self.assertEqual(Connect.getPage(url=url, host=host, auxHeaders=aux)[0], "ok")
                hostLines = [line for line in sockets[-1].handshake.split(b"\r\n") if line.lower().startswith(b"host:")]
                self.assertEqual(len(hostLines), 1)
                self.assertEqual(hostLines[0].split(b":", 1)[1].strip(), expected.encode("ascii"))
        finally:
            Connect.getPage = oldGetPage
            W.socket.create_connection = original
            socket.setdefaulttimeout(oldTimeout)
            conf.clear(); conf.update(oldConf)
            kb.clear(); kb.update(oldKb)
            threadData.__dict__.clear(); threadData.__dict__.update(oldThreadData)
            os.unlink(headersFile)


if __name__ == "__main__":
    unittest.main()
