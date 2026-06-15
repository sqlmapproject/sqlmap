#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Target URL parsing (lib/core/common.py parseTargetUrl).

parseTargetUrl reads conf.url and populates conf.hostname / conf.port /
conf.scheme / conf.path - the values every subsequent request is built from. A
wrong default port or dropped scheme here misdirects the entire scan, so the
scheme/default-port/explicit-port/path cases are pinned.

(Inline URL credentials user:pw@host are intentionally not covered - sqlmap
uses --auth-cred for that and does not parse them out of conf.url.)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import parseTargetUrl
from lib.core.data import conf


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
