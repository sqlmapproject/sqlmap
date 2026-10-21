#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit tests for lib/request/httpshandler.py, exercising the SSL protocol
candidate selection.

No network is involved: the module is reimported with chosen ssl.PROTOCOL_*
constants removed, mimicking OpenSSL builds that have those protocol versions
compiled out (e.g. OPENSSL_NO_TLS1), as the constants are conditional there.
"""

import os
import ssl
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap

bootstrap()

from lib.core.data import conf
import lib.request.httpshandler as hmod
from thirdparty.six.moves import reload_module as _reload_module

class TestProtocolSelection(unittest.TestCase):
    def tearDown(self):
        hmod.socket.create_connection = self._createConnection
        hmod.ssl.SSLContext = self._sslContext
        hmod._contexts.clear()

        for name, value in self._removed.items():
            setattr(ssl, name, value)
        _reload_module(hmod)

    def _reload_without(self, *names):
        """Reloads the module with `names` missing from ssl (as on builds lacking those protocols)"""

        self._removed = {}
        self._createConnection = hmod.socket.create_connection
        self._sslContext = hmod.ssl.SSLContext

        for name in names:
            if hasattr(ssl, name):
                self._removed[name] = getattr(ssl, name)
                delattr(ssl, name)

        _reload_module(hmod)

        return [hmod._lut.get(_, _) for _ in hmod._protocols if _ in hmod._tlsProtocols]

    def test_only_tls_protocols_are_used_with_sni(self):
        # Note: SSL era protocols stay in _protocols for the non-SNI fallback, but carry no server_hostname
        selected = self._reload_without()
        self.assertTrue(selected)
        for name in ("PROTOCOL_SSLv3", "PROTOCOL_SSLv23", "PROTOCOL_SSLv2"):
            if hasattr(ssl, name):
                self.assertIn(getattr(ssl, name), hmod._protocols)
                self.assertNotIn(getattr(ssl, name), hmod._tlsProtocols)

    def test_missing_tlsv1_does_not_raise(self):
        # Note: ssl.PROTOCOL_TLSv1 is compiled in only '#ifndef OPENSSL_NO_TLS1' (used to raise an AttributeError here)
        selected = self._reload_without("PROTOCOL_TLSv1")
        self.assertTrue(selected)
        self.assertNotIn("PROTOCOL_TLSv1", selected)

    def test_missing_all_legacy_tls_does_not_raise(self):
        selected = self._reload_without("PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1")
        self.assertTrue(selected)
        self.assertNotIn("PROTOCOL_TLSv1_1", selected)

    def test_connect_without_tlsv1(self):
        """Drives the real connect() loop, which used to reference ssl.PROTOCOL_TLSv1 directly"""

        selected = self._reload_without("PROTOCOL_TLSv1")

        conf.host = None
        conf.httpHeaders = []

        class _Context(object):
            def __init__(self, protocol):
                self.protocol = protocol

            def set_ciphers(self, _):
                pass

            def wrap_socket(self, sock, **kwargs):
                return "wrapped:%s" % hmod._lut.get(self.protocol, self.protocol)

        connection = hmod.HTTPSConnection("example.com", 443)

        # Note: stubbed only after the instantiation, as that one resolves the default context through ssl itself
        hmod.socket.create_connection = lambda *args, **kwargs: _Socket()
        hmod.ssl.SSLContext = _Context
        hmod._contexts.clear()

        connection.connect()

        self.assertEqual(connection.sock, "wrapped:%s" % selected[0])

class _Socket(object):
    def close(self):
        pass

if __name__ == "__main__":
    unittest.main()
