#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Pure / near-pure parsers and state helpers in lib/core/common.py that are NOT
already exercised by tests/test_common_utils.py.

Covered here:
  * proxy-log parsers reached through parseRequestFile()
    (_parseBurpLog plain log, _parseBurpLog Burp XML history, _parseWebScarabLog)
  * parseTargetDirect() non-smoke branch (driver resolution for SQLite)
  * removeReflectiveValues() reflected-payload masking
  * findPageForms() HTML <form> and inline JS POST discovery
  * saveConfig() .ini serialization
  * getSQLSnippet() proc-file loading + variable substitution
  * checkSystemEncoding() (no-op on a normal default encoding)
  * Format.getOs() fingerprint humanizer
  * Backend setters/getters (setOs/getOs, setOsVersion, setOsServicePack,
    setVersion/getVersion/setVersionList)
  * urlencode() extra branches (LIKE percent-encoding, convall, limit, direct)
  * safeStringFormat() extra branches (PAYLOAD_DELIMITER region, scalar percent)

Everything is run in isolation (no network, no DBMS). Any function that
reads/writes global conf/kb/Backend state has that state saved and restored
around the call so test ordering stays irrelevant. Temp files go to the
session scratchpad and are removed.
"""

import os
import sys
import base64
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.common import (
    parseRequestFile,
    parseTargetDirect,
    removeReflectiveValues,
    findPageForms,
    saveConfig,
    getSQLSnippet,
    checkSystemEncoding,
    urlencode,
    safeStringFormat,
    Format,
    Backend,
)
from lib.core.data import kb, conf
from lib.core.enums import DBMS, HTTPMETHOD
from lib.core.settings import REFLECTED_VALUE_MARKER, PAYLOAD_DELIMITER

SCRATCH = "/tmp/claude-1000/-tmp-tmp-oUnlQJzlQN/fcd55d25-6313-49ed-817e-dcbe7fc2bf22/scratchpad"


def _write_temp(content, suffix):
    """Write `content` (str) to a scratchpad temp file, return its path."""
    if not os.path.isdir(SCRATCH):
        os.makedirs(SCRATCH)
    handle, path = tempfile.mkstemp(suffix=suffix, dir=SCRATCH)
    os.write(handle, content.encode("utf-8") if isinstance(content, str) else content)
    os.close(handle)
    return path


class TestParseRequestFileBurp(unittest.TestCase):
    """_parseBurpLog via parseRequestFile (plain '=====' log + Burp XML history)."""

    def setUp(self):
        self._scope = conf.scope
        self._method = conf.method
        self._headers = conf.headers
        conf.scope = None

    def tearDown(self):
        conf.scope = self._scope
        conf.method = self._method
        conf.headers = self._headers

    def test_plain_burp_log_get(self):
        content = (
            "======================================================\n"
            "GET http://www.target.com:80/vuln.php?id=1 HTTP/1.1\n"
            "Host: www.target.com\n"
            "Cookie: PHPSESSID=abc\n"
            "======================================================\n"
        )
        path = _write_temp(content, ".log")
        try:
            targets = list(parseRequestFile(path))
        finally:
            os.unlink(path)

        self.assertEqual(len(targets), 1)
        url, method, data, cookie, headers = targets[0]
        self.assertEqual(url, "http://www.target.com:80/vuln.php?id=1")
        self.assertEqual(method, HTTPMETHOD.GET)
        self.assertIsNone(data)
        self.assertEqual(cookie, "PHPSESSID=abc")
        self.assertIn(("Host", "www.target.com"), headers)

    def test_burp_xml_history_base64_request(self):
        req = "GET /vuln.php?id=1 HTTP/1.1\r\nHost: www.target.com\r\nCookie: SID=xyz\r\n\r\n"
        b64 = base64.b64encode(req.encode()).decode()
        xml = ('<items><item><port>80</port>'
               '<request base64="true"><![CDATA[%s]]></request>'
               '</item></items>' % b64)
        path = _write_temp(xml, ".xml")
        try:
            targets = list(parseRequestFile(path))
        finally:
            os.unlink(path)

        self.assertEqual(len(targets), 1)
        url, method, data, cookie, headers = targets[0]
        self.assertEqual(url, "http://www.target.com:80/vuln.php?id=1")
        self.assertEqual(method, HTTPMETHOD.GET)
        self.assertEqual(cookie, "SID=xyz")

    def test_post_body_captured(self):
        content = (
            "======================================================\n"
            "POST http://www.target.com:80/login HTTP/1.1\n"
            "Host: www.target.com\n"
            "Content-Length: 17\n"
            "\n"
            "user=admin&pw=1\n"
            "======================================================\n"
        )
        path = _write_temp(content, ".log")
        try:
            targets = list(parseRequestFile(path))
        finally:
            os.unlink(path)

        self.assertEqual(len(targets), 1)
        url, method, data, cookie, headers = targets[0]
        self.assertEqual(method, HTTPMETHOD.POST)
        self.assertEqual(data, "user=admin&pw=1")

    def test_scope_filters_out_nonmatching(self):
        content = (
            "======================================================\n"
            "GET http://www.target.com:80/vuln.php?id=1 HTTP/1.1\n"
            "Host: www.target.com\n"
            "======================================================\n"
        )
        path = _write_temp(content, ".log")
        try:
            conf.scope = r"example\.org"  # does not match target.com
            targets = list(parseRequestFile(path))
        finally:
            os.unlink(path)
        self.assertEqual(targets, [])


class TestParseRequestFileWebScarab(unittest.TestCase):
    """_parseWebScarabLog via parseRequestFile."""

    def setUp(self):
        self._scope = conf.scope
        conf.scope = None

    def tearDown(self):
        conf.scope = self._scope

    def test_get_conversation(self):
        content = (
            "### Conversation : 1\n"
            "URL: http://www.target.com/vuln.php?id=1\n"
            "METHOD: GET\n"
            "COOKIE: SID=abc\n"
        )
        path = _write_temp(content, ".log")
        try:
            targets = list(parseRequestFile(path))
        finally:
            os.unlink(path)

        self.assertEqual(len(targets), 1)
        url, method, data, cookie, headers = targets[0]
        self.assertEqual(url, "http://www.target.com/vuln.php?id=1")
        self.assertEqual(method, "GET")
        self.assertIsNone(data)
        self.assertEqual(cookie, "SID=abc")
        self.assertEqual(headers, tuple())

    def test_post_conversation_skipped(self):
        # POST bodies live in separate files -> WebScarab POSTs are skipped
        content = (
            "### Conversation : 1\n"
            "URL: http://www.target.com/login\n"
            "METHOD: POST\n"
        )
        path = _write_temp(content, ".log")
        try:
            targets = list(parseRequestFile(path))
        finally:
            os.unlink(path)
        self.assertEqual(targets, [])


class TestParseTargetDirectNonSmoke(unittest.TestCase):
    """parseTargetDirect() non-smoke branch: resolves the canonical DBMS name.

    Uses SQLite because its driver (stdlib sqlite3) is always importable.
    """

    _KEYS = ("direct", "dbms", "dbmsUser", "dbmsPass", "dbmsDb", "hostname", "port")

    def setUp(self):
        self._saved = {k: conf.get(k) for k in self._KEYS}
        self._smoke = kb.smokeMode
        self._params_none = conf.parameters.get(None)

    def tearDown(self):
        for k, v in self._saved.items():
            conf[k] = v
        kb.smokeMode = self._smoke
        if self._params_none is None:
            conf.parameters.pop(None, None)
        else:
            conf.parameters[None] = self._params_none

    def test_sqlite_local_dsn(self):
        kb.smokeMode = False
        conf.direct = "sqlite://%s" % os.path.join(SCRATCH, "test.db")
        parseTargetDirect()
        # non-smoke path canonicalizes the DBMS name via DBMS_DICT
        self.assertEqual(conf.dbms, DBMS.SQLITE)
        # local file DBMS: hostname forced to localhost, port 0
        self.assertEqual(conf.hostname, "localhost")
        self.assertEqual(conf.port, 0)
        self.assertEqual(conf.parameters[None], "direct connection")


class TestRemoveReflectiveValues(unittest.TestCase):
    def setUp(self):
        self._mech = kb.reflectiveMechanism
        self._heur = kb.heuristicMode
        kb.reflectiveMechanism = True
        kb.heuristicMode = False

    def tearDown(self):
        kb.reflectiveMechanism = self._mech
        kb.heuristicMode = self._heur

    def test_reflected_payload_masked(self):
        content = u"<html>You searched for 1 AND 1=2 here</html>"
        out = removeReflectiveValues(content, "1 AND 1=2")
        self.assertIn(REFLECTED_VALUE_MARKER, out)
        self.assertNotIn("AND 1=2", out)

    def test_no_reflection_returns_content_unchanged(self):
        content = u"<html>nothing interesting</html>"
        out = removeReflectiveValues(content, "1 AND 1=2")
        self.assertEqual(out, content)

    def test_none_payload_returns_content(self):
        content = u"<html>x</html>"
        self.assertEqual(removeReflectiveValues(content, None), content)

    def test_bytes_content_returned_as_is(self):
        # non-text content short-circuits (isinstance text_type check)
        content = b"<html>1 AND 1=2</html>"
        self.assertEqual(removeReflectiveValues(content, "1 AND 1=2"), content)


class TestFindPageForms(unittest.TestCase):
    def setUp(self):
        self._scope = conf.scope
        self._crawlExclude = conf.crawlExclude
        self._cookie = conf.cookie
        conf.scope = None
        conf.crawlExclude = None
        conf.cookie = None

    def tearDown(self):
        conf.scope = self._scope
        conf.crawlExclude = self._crawlExclude
        conf.cookie = self._cookie

    def test_post_form_discovered(self):
        html = ('<html><form action="/input.php" method="POST">'
                '<input type="text" name="id" value="1">'
                '<input type="submit" value="Go"></form></html>')
        forms = findPageForms(html, "http://www.site.com")
        self.assertEqual(forms, set([("http://www.site.com/input.php", "POST", "id=1", None, None)]))

    def test_get_form_discovered(self):
        html = ('<html><form action="/search" method="GET">'
                '<input type="text" name="q" value="x">'
                '<input type="submit" value="Go"></form></html>')
        forms = findPageForms(html, "http://www.site.com")
        self.assertEqual(len(forms), 1)
        url, method, data, _cookie, _ = list(forms)[0]
        self.assertEqual(method, "GET")
        self.assertIn("q=x", url)

    def test_inline_js_post_discovered(self):
        # the `.post('url', {k: v})` regex branch (independent of HTML form parsing)
        html = "<script>$.post('/api/save', {name: 'foo', id: '1'});</script>"
        forms = findPageForms(html, "http://www.site.com")
        self.assertTrue(any(m == HTTPMETHOD.POST and u.endswith("/api/save") for (u, m, d, c, e) in forms))

    def test_blank_content_returns_empty_set(self):
        self.assertEqual(findPageForms("", "http://www.site.com"), set())


class TestSaveConfig(unittest.TestCase):
    def test_writes_ini_with_sections(self):
        path = _write_temp("", ".ini")
        try:
            saveConfig(conf, path)
            with open(path) as f:
                data = f.read()
        finally:
            os.unlink(path)

        # optDict families become [Section] headers
        self.assertIn("[Target]", data)
        self.assertIn("[Request]", data)
        self.assertIn("[Enumeration]", data)
        self.assertTrue(len(data) > 0)


class TestGetSQLSnippet(unittest.TestCase):
    def test_mssql_proc_loaded(self):
        snippet = getSQLSnippet(DBMS.MSSQL, "activate_sp_oacreate")
        self.assertIn("RECONFIGURE", snippet)

    def test_variable_substitution(self):
        # %VAR% placeholders are substituted from kwargs (here %ENABLE%);
        # supplying it avoids the interactive "provide substitution values" prompt.
        snippet = getSQLSnippet(DBMS.MSSQL, "configure_xp_cmdshell", ENABLE="1")
        self.assertIn("xp_cmdshell", snippet)
        self.assertIn("RECONFIGURE", snippet)
        # comments (#...) are stripped and the placeholder is fully resolved
        self.assertNotIn("#", snippet)
        self.assertNotIn("%ENABLE%", snippet)


class TestCheckSystemEncoding(unittest.TestCase):
    def test_noop_on_normal_encoding(self):
        # On a normal default encoding this is a no-op and must not raise.
        self.assertIsNone(checkSystemEncoding())


class TestFormatGetOs(unittest.TestCase):
    def setUp(self):
        self._api = conf.api
        conf.api = False

    def tearDown(self):
        conf.api = self._api

    def test_humanizes_type_and_technology(self):
        info = {
            "type": set(["Linux"]),
            "distrib": set(["Ubuntu"]),
            "release": set(["8.10"]),
            "technology": set(["PHP 5.2.6", "Apache 2.2.9"]),
        }
        out = Format.getOs("back-end DBMS", info)
        self.assertTrue(out.startswith("back-end DBMS operating system: Linux"))
        self.assertIn("Ubuntu", out)
        self.assertIn("8.10", out)
        self.assertIn("web application technology:", out)

    def test_api_mode_returns_dict(self):
        orig = conf.api
        try:
            conf.api = True
            info = {"type": set(["Windows"]), "technology": set(["IIS"])}
            out = Format.getOs("back-end DBMS", info)
            self.assertIsInstance(out, dict)
            self.assertIn("web application technology", out)
        finally:
            conf.api = orig


class TestBackendSetters(unittest.TestCase):
    """Backend OS/version setters write kb state; save and restore it."""

    _KEYS = ("os", "osVersion", "osSP", "dbmsVersion")

    def setUp(self):
        self._saved = {k: kb.get(k) for k in self._KEYS}

    def tearDown(self):
        for k, v in self._saved.items():
            kb[k] = v

    def test_set_get_os(self):
        kb.os = None
        self.assertEqual(Backend.setOs("windows"), "Windows")  # capitalized
        self.assertEqual(Backend.getOs(), "Windows")

    def test_set_os_none_returns_none(self):
        self.assertIsNone(Backend.setOs(None))

    def test_set_os_version(self):
        kb.osVersion = None
        Backend.setOsVersion("2008")
        self.assertEqual(Backend.getOsVersion(), "2008")

    def test_set_os_service_pack(self):
        kb.osSP = None
        Backend.setOsServicePack(3)
        self.assertEqual(Backend.getOsServicePack(), 3)

    def test_set_get_version(self):
        kb.dbmsVersion = []
        self.assertEqual(Backend.setVersion("5.7"), ["5.7"])
        self.assertEqual(Backend.getVersion(), "5.7")

    def test_set_version_list(self):
        kb.dbmsVersion = []
        Backend.setVersionList(["8.0", "8.1"])
        self.assertEqual(Backend.getVersionList(), ["8.0", "8.1"])


class TestUrlencodeExtraBranches(unittest.TestCase):
    def test_like_percent_encoded(self):
        # '%' inside a LIKE '...' literal is encoded to %25
        self.assertEqual(urlencode("AND name LIKE '%DBA%'"),
                         "AND%20name%20LIKE%20%27%25DBA%25%27")

    def test_convall_drops_safe_set(self):
        self.assertEqual(urlencode("a&b", convall=True), "a%26b")

    def test_limit_does_not_crash_on_long_input(self):
        out = urlencode("x " * 4000, limit=True)
        self.assertTrue(len(out) > 0)

    def test_direct_mode_returns_value_unchanged(self):
        orig = conf.direct
        try:
            conf.direct = "mysql://u:p@h:3306/d"
            self.assertEqual(urlencode("a b"), "a b")
        finally:
            conf.direct = orig


class TestSafeStringFormatExtraBranches(unittest.TestCase):
    def test_percent_d_in_payload_region_becomes_string(self):
        fmt = "SELECT %s" + PAYLOAD_DELIMITER + " AND %d " + PAYLOAD_DELIMITER
        self.assertEqual(
            safeStringFormat(fmt, ("a", "5")),
            "SELECT a" + PAYLOAD_DELIMITER + " AND 5 " + PAYLOAD_DELIMITER)

    def test_scalar_string_percent_preserved(self):
        # single-string param path: plain replace, embedded '%' survives
        self.assertEqual(safeStringFormat("LIKE %s", "100%done"), "LIKE 100%done")

    def test_two_params_list(self):
        self.assertEqual(safeStringFormat("%s/%s", ("a", "b")), "a/b")


if __name__ == "__main__":
    unittest.main(verbosity=2)
