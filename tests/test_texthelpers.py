#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Text-processing helpers in lib/core/common.py:
normalizeUnicode (accent folding), filterStringValue (charset whitelist),
parseFilePaths (absolute-path harvesting from error pages -> kb.absFilePaths),
getSafeExString (safe exception rendering).

parseFilePaths in particular feeds path disclosure / file-read targeting, so
its extraction is pinned with realistic PHP/ASP error strings.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import normalizeUnicode, filterStringValue, parseFilePaths, getSafeExString
from lib.core.data import kb


class TestNormalizeUnicode(unittest.TestCase):
    def test_strips_accents(self):
        self.assertEqual(normalizeUnicode(u"caf\xe9 r\xe9sum\xe9"), u"cafe resume")

    def test_ascii_unchanged(self):
        self.assertEqual(normalizeUnicode(u"plain ascii 123"), u"plain ascii 123")


class TestFilterStringValue(unittest.TestCase):
    def test_keep_lowercase(self):
        self.assertEqual(filterStringValue("abc123!@#", r"[a-z]"), "abc")

    def test_keep_digits(self):
        self.assertEqual(filterStringValue("a1b2c3", r"[0-9]"), "123")

    def test_all_match(self):
        self.assertEqual(filterStringValue("abc", r"[a-z]"), "abc")


class TestParseFilePaths(unittest.TestCase):
    def setUp(self):
        self.addCleanup(setattr, kb, "absFilePaths", kb.get("absFilePaths"))
        kb.absFilePaths = set()

    def test_unix_paths_from_php_error(self):
        parseFilePaths("Warning: include(/var/www/html/config.php) failed "
                       "to open stream in /var/www/html/index.php on line 5")
        self.assertIn("/var/www/html/config.php", kb.absFilePaths)
        self.assertIn("/var/www/html/index.php", kb.absFilePaths)

    def test_windows_path(self):
        # exact full path (not a substring) - a truncated harvest is a real defect for file-read targeting
        parseFilePaths("Fatal error in C:\\inetpub\\wwwroot\\app\\index.asp on line 1")
        self.assertIn("C:\\inetpub\\wwwroot\\app\\index.asp", kb.absFilePaths,
                      msg="windows path not harvested in full: %s" % kb.absFilePaths)

    def test_quoted_paths_harvested(self):
        # paths delimited by a leading quote (Python/Java/.NET stack traces) must be harvested too
        parseFilePaths('File "/usr/lib/python3.11/site-packages/app.py", line 10')
        parseFilePaths("Cannot read '/opt/tomcat/webapps/app/WEB-INF/web.xml' now")
        parseFilePaths('Could not find file "C:\\data\\config.ini".')
        self.assertIn("/usr/lib/python3.11/site-packages/app.py", kb.absFilePaths)
        self.assertIn("/opt/tomcat/webapps/app/WEB-INF/web.xml", kb.absFilePaths)
        self.assertIn("C:\\data\\config.ini", kb.absFilePaths)

    def test_quoted_non_path_ignored(self):
        # a leading quote must not turn ordinary quoted words or URLs into "paths"
        parseFilePaths("error: 'foobar' invalid; see 'https://example.com/help' for info")
        self.assertEqual(kb.absFilePaths, set())


class TestGetSafeExString(unittest.TestCase):
    def test_format(self):
        self.assertEqual(getSafeExString(ValueError("boom")), u"ValueError: boom")

    def test_runtime_error(self):
        # RuntimeError keeps its name across py2/py3 (unlike IOError, which aliases to OSError on py3)
        self.assertEqual(getSafeExString(RuntimeError("oops")), u"RuntimeError: oops")


if __name__ == "__main__":
    unittest.main(verbosity=2)
