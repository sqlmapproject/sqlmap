#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Target URL parsing (lib/core/common.py parseTargetUrl).

parseTargetUrl reads conf.url and populates conf.hostname / conf.port /
conf.scheme / conf.path - the values every subsequent request is built from. A
wrong default port or dropped scheme here misdirects the entire scan, so the
scheme/default-port/explicit-port/path cases are pinned.

Inline URL credentials (user:pw@host) are stripped so the host/port parse
correctly - previously the userinfo was mistaken for the host (user:pass@host ->
hostname 'user'). The credentials are still NOT used for authentication (sqlmap
warns and expects --auth-cred); only the host-misparse is fixed.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import parseTargetUrl
from lib.core.data import conf

_TARGETURL_KEYS = ("url", "hostname", "port", "scheme", "path")
_saved = {}


def setUpModule():
    for k in _TARGETURL_KEYS:
        _saved[k] = conf.get(k)


def tearDownModule():
    # parseTargetUrl() writes these onto the global conf singleton; restore so it can't leak to later modules
    for k, v in _saved.items():
        conf[k] = v


def _parse(url):
    conf.url = url
    parseTargetUrl()
    return conf.hostname, conf.port, conf.scheme, conf.path


class TestScheme(unittest.TestCase):
    def test_http(self):
        host, port, scheme, _ = _parse("http://host/p?id=1")
        self.assertEqual((host, scheme), ("host", "http"))

    def test_https(self):
        _, _, scheme, _ = _parse("https://host/p")
        self.assertEqual(scheme, "https")


class TestDefaultPorts(unittest.TestCase):
    def test_http_default_80(self):
        self.assertEqual(_parse("http://h/")[1], 80)

    def test_https_default_443(self):
        self.assertEqual(_parse("https://h/")[1], 443)

    def test_no_trailing_slash(self):
        host, port, scheme, _ = _parse("http://h")
        self.assertEqual((host, port), ("h", 80))


class TestExplicitPort(unittest.TestCase):
    def test_explicit_port(self):
        host, port, scheme, _ = _parse("https://example.com:8443/x")
        self.assertEqual((host, port, scheme), ("example.com", 8443, "https"))


class TestPath(unittest.TestCase):
    def test_path_extracted(self):
        self.assertEqual(_parse("http://host/some/path?q=1")[3], "/some/path")


class TestInlineCredentials(unittest.TestCase):
    """Userinfo (user:pw@) must be stripped from the host, not mistaken for it."""

    def test_user_pass_with_port(self):
        host, port, _, _ = _parse("http://user:pass@host:8080/?id=1")
        self.assertEqual((host, port), ("host", 8080))

    def test_user_pass_default_port(self):
        host, port, _, _ = _parse("http://user:pass@host/?id=1")
        self.assertEqual((host, port), ("host", 80))

    def test_user_only(self):
        self.assertEqual(_parse("http://user@host/?id=1")[0], "host")

    def test_credentials_with_ipv6(self):
        host, port, _, _ = _parse("http://user:pass@[::1]:8443/?id=1")
        self.assertEqual((host, port), ("::1", 8443))


if __name__ == "__main__":
    unittest.main(verbosity=2)
