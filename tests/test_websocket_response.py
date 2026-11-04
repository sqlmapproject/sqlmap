#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import base64
import hashlib
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf, kb
from lib.core.exception import SqlmapConnectionException
from lib.core.option import _setKnowledgeBaseAttributes
from lib.core.threads import getCurrentThreadData
from lib.request.connect import Connect
import lib.request.websocket as websocket

_GET_PAGE = Connect.__dict__["getPage"]


def _frame(payload, opcode=1, fin=1):
    return bytes(bytearray([(fin << 7) | opcode, len(payload)])) + payload


class _Socket(object):
    def __init__(self, frames):
        self.frames = frames
        self.response = b""
        self.handshake = None

    def settimeout(self, value):
        pass

    def sendall(self, data):
        if self.handshake is None:
            self.handshake = data
            key = next(line.split(b":", 1)[1].strip() for line in data.split(b"\r\n") if line.lower().startswith(b"sec-websocket-key:"))
            accept = base64.b64encode(hashlib.sha1(key + websocket._GUID.encode("ascii")).digest())
            self.response = b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n" + self.frames

    def recv(self, size):
        result, self.response = self.response[:size], self.response[size:]
        return result

    def close(self):
        pass


class TestWebSocketResponseClose(unittest.TestCase):
    def setUp(self):
        self.oldConf, self.oldKb = dict(conf), dict(kb)
        self.threadData = getCurrentThreadData()
        self.oldThreadData = dict(self.threadData.__dict__)
        self.oldTimeout = socket.getdefaulttimeout()
        self.oldSocket = websocket.socket.create_connection
        self.oldGetPage = Connect.__dict__["getPage"]
        self.threadData.__dict__.clear()
        self.threadData.reset()
        _setKnowledgeBaseAttributes(False)
        kb.wizardMode = True
        conf.url = "ws://example.test:8080/test"
        conf.hostname, conf.scheme, conf.port, conf.path = "example.test", "ws", 8080, "/test"
        conf.httpHeaders, conf.parameters, conf.data = [], {}, None
        conf.abortCode, conf.ignoreCode = [], []
        conf.timeout, conf.batch, conf.keepAlive, conf.retries = 3, True, False, 0
        conf.retryOn, conf.ignoreRedirects, conf.scope = None, False, None
        Connect.getPage = _GET_PAGE
        websocket.socket.create_connection = lambda *args, **kwargs: _Socket(self.frames)

    def tearDown(self):
        Connect.getPage = self.oldGetPage
        websocket.socket.create_connection = self.oldSocket
        socket.setdefaulttimeout(self.oldTimeout)
        conf.clear(); conf.update(self.oldConf)
        kb.clear(); kb.update(self.oldKb)
        self.threadData.__dict__.clear(); self.threadData.__dict__.update(self.oldThreadData)

    def test_normal_close_after_response(self):
        for status in (b"", struct.pack("!H", 1000), struct.pack("!H", 1001)):
            for count in (None, 3):
                self.frames = _frame(b"one") + _frame(b"two") + _frame(status, opcode=8)
                kb.webSocketRecvCount = count
                self.assertEqual(Connect.getPage(url=conf.url)[0], "one\ntwo")
                if count is None:
                    self.assertEqual(kb.webSocketRecvCount, 2)

    def test_normal_close_without_response(self):
        self.frames = _frame(struct.pack("!H", 1000), opcode=8)
        kb.webSocketRecvCount = None
        self.assertEqual(Connect.getPage(url=conf.url)[0], "")
        self.assertEqual(kb.webSocketRecvCount, 0)

    def test_abnormal_close_remains_an_error(self):
        for status in (b"\x03", struct.pack("!H", 1002), struct.pack("!H", 1011)):
            self.frames = _frame(b"one") + _frame(status, opcode=8)
            for count in (None, 3):
                kb.webSocketRecvCount = count
                self.assertRaises(SqlmapConnectionException, Connect.getPage, url=conf.url)

    def test_truncated_frame_remains_an_error(self):
        for frames in (_frame(b"one"), _frame(b"one") + b"\x81\x05ab"):
            self.frames = frames
            for count in (None, 3):
                kb.webSocketRecvCount = count
                self.assertRaises(SqlmapConnectionException, Connect.getPage, url=conf.url)

    def test_close_during_fragmented_message_remains_an_error(self):
        for fragment in (b"", b"partial"):
            self.frames = _frame(fragment, fin=0) + _frame(struct.pack("!H", 1000), opcode=8)
            kb.webSocketRecvCount = None
            self.assertRaises(SqlmapConnectionException, Connect.getPage, url=conf.url)


if __name__ == "__main__":
    unittest.main()
