#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

# Native, dependency-free WebSocket client (RFC 6455), replacing the 'websocket-client' third-party
# library. Covers exactly what sqlmap needs: the client handshake, masked text framing, wss (TLS) and
# the recv/timeout surface. It also removes the long-standing ambiguity with the unrelated 'websocket'
# PyPI package (both expose a top-level 'websocket' module). Pure standard library, Python 2.7 / 3.x.

import base64
import hashlib
import os
import socket
import ssl
import struct

from lib.core.convert import getBytes
from lib.core.convert import getText
from thirdparty.six.moves import urllib as _urllib

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"    # RFC 6455 magic value for the accept key

OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

class WebSocketException(Exception):
    pass

class WebSocketTimeoutException(WebSocketException):
    pass

class WebSocketConnectionClosedException(WebSocketException):
    pass

class WebSocket(object):
    """
    Minimal RFC 6455 client exposing the websocket-client subset used by sqlmap: settimeout(), connect(),
    send(), recv(), close(), the handshake .status and getheaders()
    """

    def __init__(self):
        self.sock = None
        self.status = None
        self._headers = {}
        self._timeout = None
        self._buffer = b""
        self._closed = False

    def settimeout(self, timeout):
        self._timeout = timeout
        if self.sock is not None:
            self.sock.settimeout(timeout)

    def connect(self, url, header=None, cookie=None):
        parts = _urllib.parse.urlsplit(url)
        secure = parts.scheme == "wss"
        host = parts.hostname
        port = parts.port or (443 if secure else 80)
        resource = parts.path or "/"
        if parts.query:
            resource += "?%s" % parts.query

        self.sock = socket.create_connection((host, port), timeout=self._timeout)
        if secure:
            self.sock = ssl._create_unverified_context().wrap_socket(self.sock, server_hostname=host)
        self.sock.settimeout(self._timeout)

        hostport = "[%s]" % host if ":" in host else host       # bracket IPv6 literals
        if port not in (80, 443):
            hostport = "%s:%d" % (hostport, port)

        key = getText(base64.b64encode(os.urandom(16)))
        lines = ["GET %s HTTP/1.1" % resource,
                 "Host: %s" % hostport,
                 "Upgrade: websocket",
                 "Connection: Upgrade",
                 "Sec-WebSocket-Key: %s" % key,
                 "Sec-WebSocket-Version: 13"]
        for _ in (header or ()):
            lines.append(_)
        if cookie:
            lines.append("Cookie: %s" % cookie)
        lines.extend(("", ""))
        self.sock.sendall(getBytes("\r\n".join(lines)))

        self._readHandshake(key)

    def _readHandshake(self, key):
        while b"\r\n\r\n" not in self._buffer:
            chunk = self._recvSome()
            if not chunk:
                raise WebSocketException("incomplete WebSocket handshake response")
            self._buffer += chunk

        head, _, self._buffer = self._buffer.partition(b"\r\n\r\n")
        lines = getText(head).split("\r\n")

        try:
            self.status = int(lines[0].split(" ", 2)[1])
        except (IndexError, ValueError):
            raise WebSocketException("malformed WebSocket handshake response")

        for line in lines[1:]:
            name, _, value = line.partition(":")
            self._headers[name.strip().lower()] = value.strip()

        if self.status != 101:
            raise WebSocketException("Handshake status %d" % self.status)      # 'Handshake status' is matched in connect.py

        accept = getText(self._headers.get("sec-websocket-accept", ""))
        expected = getText(base64.b64encode(hashlib.sha1(getBytes(key + _GUID)).digest()))
        if accept != expected:
            raise WebSocketException("invalid 'Sec-WebSocket-Accept' in handshake response")

    def getheaders(self):
        return dict(self._headers)

    def send(self, payload, opcode=OPCODE_TEXT):
        self._sendFrame(getBytes(payload), opcode)

    def _sendFrame(self, data, opcode):
        length = len(data)
        frame = bytearray()
        frame.append(0x80 | opcode)                    # FIN set, single (unfragmented) frame

        if length < 126:
            frame.append(0x80 | length)                # client frames must set the mask bit
        elif length < 65536:
            frame.append(0x80 | 126)
            frame += struct.pack("!H", length)
        else:
            frame.append(0x80 | 127)
            frame += struct.pack("!Q", length)

        mask = bytearray(os.urandom(4))
        frame += mask
        payload = bytearray(data)
        for i in range(length):
            payload[i] ^= mask[i % 4]
        frame += payload

        try:
            self.sock.sendall(bytes(frame))
        except socket.timeout:
            raise WebSocketTimeoutException("timed out while sending data")
        except ssl.SSLError as ex:
            if "timed out" in str(ex).lower():
                raise WebSocketTimeoutException("timed out while sending data")
            raise

    def recv(self):
        data = bytearray()
        while True:
            fin, opcode, payload = self._recvFrame()
            if opcode == OPCODE_CLOSE:
                self._closed = True
                raise WebSocketConnectionClosedException("WebSocket connection closed")
            elif opcode == OPCODE_PING:
                self._sendFrame(bytes(payload), OPCODE_PONG)
                continue
            elif opcode == OPCODE_PONG:
                continue

            data += payload
            if fin:
                break

        return getText(bytes(data))

    def _recvFrame(self):
        header = bytearray(self._readStrict(2))
        fin = (header[0] >> 7) & 1
        opcode = header[0] & 0x0F
        masked = (header[1] >> 7) & 1
        length = header[1] & 0x7F

        if length == 126:
            length = struct.unpack("!H", self._readStrict(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._readStrict(8))[0]

        mask = bytearray(self._readStrict(4)) if masked else None
        payload = bytearray(self._readStrict(length))
        if mask is not None:                           # servers must not mask, but unmask defensively
            for i in range(length):
                payload[i] ^= mask[i % 4]

        return fin, opcode, payload

    def _readStrict(self, count):
        while len(self._buffer) < count:
            chunk = self._recvSome()
            if not chunk:
                raise WebSocketConnectionClosedException("WebSocket connection closed")
            self._buffer += chunk

        result, self._buffer = self._buffer[:count], self._buffer[count:]
        return result

    def _recvSome(self):
        try:
            return self.sock.recv(8192)
        except socket.timeout:
            raise WebSocketTimeoutException("timed out while receiving data")
        except ssl.SSLError as ex:
            # Python 2 raises ssl.SSLError('The read operation timed out') instead of socket.timeout on a
            # TLS read timeout - which is exactly sqlmap's normal "read frames until timeout" path over wss
            if "timed out" in str(ex).lower():
                raise WebSocketTimeoutException("timed out while receiving data")
            raise

    def close(self):
        if self.sock is not None:
            try:
                if not self._closed:
                    self._sendFrame(struct.pack("!H", 1000), OPCODE_CLOSE)   # normal closure
            except (socket.error, WebSocketException):
                pass
            try:
                self.sock.close()
            except socket.error:
                pass
            self.sock = None
