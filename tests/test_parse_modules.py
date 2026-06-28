#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Parsers under lib/parse/: DBMS banner fingerprinting (banner.py + the shared
FingerprintHandler in handler.py) and the .ini configuration-file reader
(configfile.py). These are pure: given a banner string (and the shipped XML
signature files) or a config file on disk, they populate kb/conf with no
network or DBMS. We drive each over realistic inputs and assert the extracted
fingerprint / parsed options.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import kb, conf
from lib.core.enums import DBMS
from lib.parse.banner import bannerParser, MSSQLBannerHandler
from lib.parse.handler import FingerprintHandler


class TestFingerprintHandler(unittest.TestCase):
    def test_feedinfo_dbms_version_scalar(self):
        info = {}
        h = FingerprintHandler("some banner", info)
        h._feedInfo("dbmsVersion", "5.7.1")
        self.assertEqual(info["dbmsVersion"], "5.7.1")

    def test_feedinfo_set_valued_keys_split_on_pipe(self):
        info = {}
        h = FingerprintHandler("some banner", info)
        h._feedInfo("type", "Linux|Debian")
        self.assertIsInstance(info["type"], set)
        self.assertEqual(info["type"], set(["Linux", "Debian"]))

    def test_feedinfo_ignores_empty_and_none(self):
        info = {}
        h = FingerprintHandler("b", info)
        h._feedInfo("type", "")
        h._feedInfo("type", "None")
        h._feedInfo("type", None)
        self.assertNotIn("type", info)


class TestBannerParser(unittest.TestCase):
    def setUp(self):
        self._saved = kb.bannerFp
        kb.bannerFp = {}

    def tearDown(self):
        kb.bannerFp = self._saved

    def test_no_dbms_is_noop(self):
        # without an identified DBMS bannerParser must bail out before touching kb.bannerFp
        from lib.core.common import Backend
        Backend.flushForcedDbms(force=True)
        saved = (conf.get("forceDbms"), kb.get("dbms"))
        conf.forceDbms = None
        kb.dbms = None
        try:
            kb.bannerFp = {}
            self.assertIsNone(bannerParser("PostgreSQL 9.5.3 on x86_64-pc-linux-gnu"))
            # no back-end identified -> the early return leaves the fingerprint untouched
            self.assertEqual(kb.bannerFp, {})
        finally:
            conf.forceDbms, kb.dbms = saved

    def test_mysql_banner_populates_version(self):
        set_dbms(DBMS.MYSQL)
        kb.bannerFp = {}
        bannerParser("5.0.51a-3ubuntu5.4")
        # the generic signatures classify the OS/distrib from the banner tail
        self.assertTrue(kb.bannerFp, msg="no fingerprint extracted")
        self.assertIn("Ubuntu", kb.bannerFp.get("distrib", set()))

    def test_oracle_banner_populates_version(self):
        set_dbms(DBMS.ORACLE)
        kb.bannerFp = {}
        bannerParser("Oracle Database 11g Enterprise Edition Release 11.2.0.1.0 - 64bit Production")
        self.assertIn("dbmsVersion", kb.bannerFp)
        self.assertTrue(kb.bannerFp["dbmsVersion"].startswith("11.2.0"))

    def test_pgsql_banner_populates_version(self):
        set_dbms(DBMS.PGSQL)
        kb.bannerFp = {}
        # the shipped PostgreSQL signature 'PostgreSQL\s+([\w\.]+)' captures the version
        bannerParser("PostgreSQL 9.5.3 on x86_64-pc-linux-gnu")
        self.assertIn("dbmsVersion", kb.bannerFp)
        self.assertEqual(kb.bannerFp["dbmsVersion"], "9.5.3")

    def test_mssql_banner_populates_release_and_version(self):
        set_dbms(DBMS.MSSQL)
        kb.bannerFp = {}
        # a real SQL Server 2008 RTM build present in data/xml/banner/mssql.xml,
        # so the MSSQLBannerHandler resolves both the release year and the version
        bannerParser("Microsoft SQL Server 2008 - 10.00.4311.00")
        self.assertEqual(kb.bannerFp.get("dbmsRelease"), "2008")
        self.assertEqual(kb.bannerFp.get("dbmsVersion"), "10.00.4311")


class TestMSSQLBannerHandler(unittest.TestCase):
    def test_version_alt_built_for_dotzero_form(self):
        info = {}
        h = MSSQLBannerHandler("Microsoft SQL Server 10.00.1600.22", info)
        h.startElement("version", {})
        h.characters("10.00.1600")
        h.endElement("version")
        # endElement('version') derives the "<major>.0.<build>.0" alternate form
        self.assertEqual(h._versionAlt, "10.0.1600.0")


class _Attrs(dict):
    """Minimal SAX-attrs stand-in (supports .get)."""


class TestMSSQLBannerHandlerServicePack(unittest.TestCase):
    def test_servicepack_strips_spaces(self):
        info = {}
        h = MSSQLBannerHandler("banner", info)
        h.startElement("servicepack", {})
        h.characters(" 2 ")
        h.endElement("servicepack")
        self.assertEqual(h._servicePack, "2")


class TestConfigFileParser(unittest.TestCase):
    def _write_cfg(self, body):
        fd, path = tempfile.mkstemp(suffix=".ini", prefix="sqlmapcfg_")
        os.close(fd)
        with open(path, "w") as f:
            f.write(body)
        return path

    def test_parses_target_and_typed_options(self):
        from lib.parse.configfile import configFileParser
        path = self._write_cfg(
            "[Target]\n"
            "url = http://config.invalid/?id=1\n"
            "[Optimization]\n"
            "threads = 4\n"
            "[Injection]\n"
            "tamper = space2comment\n"
        )
        saved = {k: conf.get(k) for k in ("url", "threads", "tamper")}
        try:
            configFileParser(path)
            self.assertEqual(conf.url, "http://config.invalid/?id=1")
            self.assertEqual(conf.threads, 4)            # INTEGER datatype coerced
            self.assertEqual(conf.tamper, "space2comment")
        finally:
            for k, v in saved.items():
                conf[k] = v
            os.remove(path)

    def test_missing_target_section_raises(self):
        from lib.parse.configfile import configFileParser
        from lib.core.exception import SqlmapMissingMandatoryOptionException
        path = self._write_cfg("[Request]\nthreads = 1\n")
        try:
            self.assertRaises(SqlmapMissingMandatoryOptionException,
                              configFileParser, path)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
