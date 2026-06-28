#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Consolidated unit coverage for lib/core/common.py.

This module merges the previously separate test_common_utils.py,
test_common_parsers.py and the common.py-specific classes from
test_core_more.py, test_core_extra.py and test_core_final.py into a single
file. Test logic is unchanged from those sources.

Everything runs in isolation (no network, no DBMS, no persistent filesystem
mutation of the project). Any function that reads/writes global conf/kb/Backend
state has that state saved and restored around the call so test ordering stays
irrelevant. Temp files go to the session scratchpad and are removed.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import base64
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.data import conf, kb, paths
from lib.core.defaults import defaults
from lib.core.enums import (
    CHARSET_TYPE,
    DBMS,
    EXPECTED,
    HTTPMETHOD,
    PLACE,
    SORT_ORDER,
)
from lib.core.exception import (
    SqlmapSystemException,
)
from lib.core.settings import (
    NULL,
    PAYLOAD_DELIMITER,
    REFLECTED_VALUE_MARKER,
)
from lib.core.common import (
    aliasToDbmsEnum,
    applyFunctionRecursively,
    arrayizeValue,
    Backend,
    boldifyMessage,
    calculateDeltaSeconds,
    checkFile,
    checkOldOptions,
    checkSystemEncoding,
    cleanReplaceUnicode,
    commonFinderOnly,
    enumValueToNameLookup,
    extractErrorMessage,
    extractExpectedValue,
    extractRegexResult,
    extractTextTagContent,
    filePathToSafeString,
    filterListValue,
    filterNone,
    filterPairValues,
    filterStringValue,
    findMultipartPostBoundary,
    findPageForms,
    flattenValue,
    Format,
    getCharset,
    getFilteredPageContent,
    getHeader,
    getLimitRange,
    getPageWordSet,
    getPartRun,
    getRequestHeader,
    getSQLSnippet,
    getTechnique,
    getText,
    intersect,
    isListLike,
    isNoneValue,
    isNullValue,
    isNumber,
    isNumPosStrValue,
    isWindowsDriveLetterPath,
    isZipFile,
    joinValue,
    listToStrValue,
    normalizeUnicode,
    paramToDict,
    parseJson,
    parsePasswordHash,
    parseRequestFile,
    parseTargetDirect,
    parseTargetUrl,
    parseUnionPage,
    removePostHintPrefix,
    removeReflectiveValues,
    resetCookieJar,
    safeExpandUser,
    safeFilepathEncode,
    safeStringFormat,
    safeSQLIdentificatorNaming,
    saveConfig,
    serializeObject,
    setTechnique,
    splitFields,
    trimAlphaNum,
    unArrayizeValue,
    unserializeObject,
    urlencode,
    zeroDepthSearch,
)

SCRATCH = "/tmp/claude-1000/-tmp-tmp-oUnlQJzlQN/fcd55d25-6313-49ed-817e-dcbe7fc2bf22/scratchpad"


def _write_temp(content, suffix):
    """Write `content` (str) to a scratchpad temp file, return its path."""
    if not os.path.isdir(SCRATCH):
        os.makedirs(SCRATCH)
    handle, path = tempfile.mkstemp(suffix=suffix, dir=SCRATCH)
    os.write(handle, content.encode("utf-8") if isinstance(content, str) else content)
    os.close(handle)
    return path


class _FakeRequest(object):
    """Minimal stand-in for urllib2.Request used by getRequestHeader()."""

    def __init__(self, headers):
        self.headers = headers

    def header_items(self):
        return self.headers.items()


# =========================================================================== #
# from tests/test_common_utils.py
# =========================================================================== #

class TestParamToDict(unittest.TestCase):
    """Parameter string -> OrderedDict for the various injection places."""

    def test_get_two_params(self):
        result = paramToDict(PLACE.GET, "id=1&name=foo")
        self.assertEqual(list(result.items()), [("id", "1"), ("name", "foo")])

    def test_get_preserves_order(self):
        result = paramToDict(PLACE.GET, "c=3&a=1&b=2")
        self.assertEqual(list(result.keys()), ["c", "a", "b"])

    def test_post_place(self):
        result = paramToDict(PLACE.POST, "user=admin&pass=secret")
        self.assertEqual(result["user"], "admin")
        self.assertEqual(result["pass"], "secret")

    def test_empty_value(self):
        result = paramToDict(PLACE.GET, "id=&name=x")
        self.assertEqual(result["id"], "")
        self.assertEqual(result["name"], "x")

    def test_value_with_equal_signs(self):
        # value is re-joined on '=' so embedded '=' survives
        result = paramToDict(PLACE.GET, "token=a=b=c")
        self.assertEqual(result["token"], "a=b=c")

    def test_cookie_delimiter(self):
        # COOKIE place splits on ';' rather than '&'
        result = paramToDict(PLACE.COOKIE, "foo=bar;baz=qux")
        self.assertEqual(list(result.items()), [("foo", "bar"), ("baz", "qux")])

    def test_param_without_equals_ignored(self):
        # an element with no '=' has len(parts) < 2 and is skipped
        result = paramToDict(PLACE.GET, "lonely&id=1")
        self.assertEqual(list(result.items()), [("id", "1")])


class TestGetCharset(unittest.TestCase):
    """Inference charsets are fixed integer tables."""

    def test_binary(self):
        self.assertEqual(getCharset(CHARSET_TYPE.BINARY), [0, 1, 47, 48, 49])

    def test_default_is_full_ascii(self):
        self.assertEqual(getCharset(None), list(range(0, 128)))

    def test_digits(self):
        result = getCharset(CHARSET_TYPE.DIGITS)
        self.assertEqual(result, list(range(0, 10)) + list(range(47, 58)))

    def test_alpha_has_no_digits(self):
        result = getCharset(CHARSET_TYPE.ALPHA)
        # ASCII codes for '0'..'9' are 48..57; ALPHA must exclude them
        self.assertFalse(any(48 <= _ <= 57 for _ in result))
        self.assertIn(ord("A"), result)
        self.assertIn(ord("z"), result)

    def test_alphanum_superset_of_alpha(self):
        alpha = set(getCharset(CHARSET_TYPE.ALPHA))
        alphanum = set(getCharset(CHARSET_TYPE.ALPHANUM))
        self.assertTrue(alpha.issubset(alphanum))
        self.assertIn(ord("5"), alphanum)

    def test_hexadecimal_contains_hex_letters(self):
        result = getCharset(CHARSET_TYPE.HEXADECIMAL)
        for ch in "0123456789abcdefABCDEF":
            self.assertIn(ord(ch), result, msg="missing %r" % ch)


class TestGetLimitRange(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(list(getLimitRange(10)), list(range(0, 10)))

    def test_plus_one(self):
        self.assertEqual(list(getLimitRange(3, plusOne=True)), [1, 2, 3])

    def test_string_count_coerced(self):
        # count is int()-coerced internally
        self.assertEqual(list(getLimitRange("4")), [0, 1, 2, 3])

    def test_length(self):
        self.assertEqual(len(getLimitRange(7)), 7)


class TestParseUnionPage(unittest.TestCase):
    def test_none(self):
        self.assertIsNone(parseUnionPage(None))

    def test_two_entries(self):
        page = "%sfoo%s%sbar%s" % (kb.chars.start, kb.chars.stop, kb.chars.start, kb.chars.stop)
        # returns a BigArray; compare element-wise
        self.assertEqual(list(parseUnionPage(page)), ["foo", "bar"])

    def test_single_entry_unwrapped(self):
        # a lone wrapped string is returned as the bare string, not a 1-element list
        page = "%shello%s" % (kb.chars.start, kb.chars.stop)
        self.assertEqual(parseUnionPage(page), "hello")

    def test_multi_column_row(self):
        # a single row whose values are joined by kb.chars.delimiter becomes one
        # nested list entry
        page = "%sa%sb%s" % (kb.chars.start, kb.chars.delimiter, kb.chars.stop)
        self.assertEqual(list(parseUnionPage(page)), [["a", "b"]])

    def test_unmarked_page_returned_verbatim(self):
        self.assertEqual(parseUnionPage("no markers here"), "no markers here")


class TestSafeStringFormat(unittest.TestCase):
    def test_basic_tuple(self):
        self.assertEqual(safeStringFormat("SELECT foo FROM %s LIMIT %d", ("bar", "1")),
                         "SELECT foo FROM bar LIMIT 1")

    def test_literal_percent_preserved(self):
        self.assertEqual(
            safeStringFormat("SELECT foo FROM %s WHERE name LIKE '%susan%' LIMIT %d", ("bar", "1")),
            "SELECT foo FROM bar WHERE name LIKE '%susan%' LIMIT 1")

    def test_single_string_param(self):
        self.assertEqual(safeStringFormat("a %s b", "X"), "a X b")

    def test_scalar_non_string(self):
        self.assertEqual(safeStringFormat("n=%d", 5), "n=5")


class TestUrlencode(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(urlencode("AND 1>(2+3)#"), "AND%201%3E%282%2B3%29%23")

    def test_none(self):
        self.assertIsNone(urlencode(None))

    def test_spaceplus(self):
        self.assertEqual(urlencode("a b", spaceplus=True), "a+b")

    def test_convall_encodes_safe_chars(self):
        # with convall the explicit 'safe' set is dropped, so '/' gets encoded
        self.assertEqual(urlencode("a/b", convall=True), "a%2Fb")

    def test_safe_char_default_kept(self):
        # by default '-' and '_' are in the safe set
        self.assertEqual(urlencode("a-b_c"), "a-b_c")


class TestParseTargetUrl(unittest.TestCase):
    """parseTargetUrl mutates conf.* in place; save and restore everything touched."""

    def _save(self):
        return {k: conf.get(k) for k in
                ("url", "scheme", "path", "hostname", "port", "ipv6")}

    def _restore(self, saved):
        for k, v in saved.items():
            conf[k] = v

    def test_https_url(self):
        saved = self._save()
        orig_params = conf.parameters.get(PLACE.GET)
        try:
            conf.url = "https://www.test.com/?id=1"
            parseTargetUrl()
            self.assertEqual(conf.hostname, "www.test.com")
            self.assertEqual(conf.scheme, "https")
            self.assertEqual(conf.port, 443)
            self.assertEqual(conf.parameters[PLACE.GET], "id=1")
        finally:
            self._restore(saved)
            if orig_params is None:
                conf.parameters.pop(PLACE.GET, None)
            else:
                conf.parameters[PLACE.GET] = orig_params

    def test_scheme_defaulted_and_port(self):
        saved = self._save()
        try:
            conf.url = "example.org:8080/app"
            parseTargetUrl()
            self.assertEqual(conf.hostname, "example.org")
            self.assertEqual(conf.scheme, "http")
            self.assertEqual(conf.port, 8080)
        finally:
            self._restore(saved)

    def test_empty_url_returns_none(self):
        saved = self._save()
        try:
            conf.url = ""
            self.assertIsNone(parseTargetUrl())
        finally:
            self._restore(saved)


class TestParseTargetDirect(unittest.TestCase):
    """parseTargetDirect under smokeMode (early-returns before driver imports)."""

    def _save(self):
        return {k: conf.get(k) for k in
                ("direct", "dbms", "dbmsUser", "dbmsPass", "dbmsDb", "hostname", "port")}

    def _restore(self, saved):
        for k, v in saved.items():
            conf[k] = v

    def test_full_mysql_dsn(self):
        saved = self._save()
        orig_smoke = kb.smokeMode
        orig_none = conf.parameters.get(None)
        try:
            kb.smokeMode = True
            conf.direct = "mysql://root:testpass@127.0.0.1:3306/testdb"
            parseTargetDirect()
            self.assertEqual(conf.dbms, "mysql")
            self.assertEqual(conf.dbmsUser, "root")
            self.assertEqual(conf.dbmsPass, "testpass")
            self.assertEqual(conf.dbmsDb, "testdb")
            self.assertEqual(conf.hostname, "127.0.0.1")
            self.assertEqual(conf.port, 3306)
        finally:
            self._restore(saved)
            kb.smokeMode = orig_smoke
            if orig_none is None:
                conf.parameters.pop(None, None)
            else:
                conf.parameters[None] = orig_none

    def test_quoted_password(self):
        saved = self._save()
        orig_smoke = kb.smokeMode
        orig_none = conf.parameters.get(None)
        try:
            kb.smokeMode = True
            conf.direct = "mysql://user:'P@ssw0rd'@127.0.0.1:3306/test"
            parseTargetDirect()
            self.assertEqual(conf.dbmsPass, "P@ssw0rd")
            self.assertEqual(conf.hostname, "127.0.0.1")
        finally:
            self._restore(saved)
            kb.smokeMode = orig_smoke
            if orig_none is None:
                conf.parameters.pop(None, None)
            else:
                conf.parameters[None] = orig_none

    def test_empty_direct_returns_none(self):
        saved = self._save()
        try:
            conf.direct = None
            self.assertIsNone(parseTargetDirect())
        finally:
            self._restore(saved)


class TestSafeSQLIdentificatorNaming(unittest.TestCase):
    """Quoting of identifiers is DBMS-specific; drive it via kb.forcedDbms."""

    def _run(self, dbms, name, **kw):
        orig = kb.forcedDbms
        try:
            kb.forcedDbms = dbms
            return getText(safeSQLIdentificatorNaming(name, **kw))
        finally:
            kb.forcedDbms = orig

    def test_mssql_keyword_bracketed(self):
        self.assertEqual(self._run(DBMS.MSSQL, "begin"), "[begin]")

    def test_plain_name_unquoted(self):
        self.assertEqual(self._run(DBMS.MSSQL, "foobar"), "foobar")

    def test_firebird_name_with_space_double_quoted(self):
        self.assertEqual(self._run(DBMS.FIREBIRD, "foo bar"), '"foo bar"')

    def test_mysql_keyword_backticked(self):
        self.assertEqual(self._run(DBMS.MYSQL, "select"), "`select`")

    def test_oracle_keyword_uppercased(self):
        # Oracle quotes AND uppercases reserved words
        self.assertEqual(self._run(DBMS.ORACLE, "table"), '"TABLE"')

    def test_unsafe_naming_passthrough(self):
        orig = conf.unsafeNaming
        try:
            conf.unsafeNaming = True
            self.assertEqual(self._run(DBMS.MYSQL, "select"), "select")
        finally:
            conf.unsafeNaming = orig


class TestGetPartRun(unittest.TestCase):
    def test_no_dbms_handler_in_stack(self):
        # called from a test (no conf.dbmsHandler.* on the stack) -> None
        self.assertIsNone(getPartRun())

    def test_non_alias_form_also_none(self):
        self.assertIsNone(getPartRun(alias=False))


# =========================================================================== #
# from tests/test_common_parsers.py
# =========================================================================== #

class TestParseRequestFileBurp(unittest.TestCase):
    """_parseBurpLog via parseRequestFile (plain '=====' log + Burp XML history)."""

    def setUp(self):
        self._scope = conf.scope
        self._method = conf.method
        self._headers = conf.headers
        conf.scope = None
        conf.method = None  # avoid a leaked conf.method overriding the parsed verb

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


# =========================================================================== #
# from tests/test_core_more.py (common.py classes)
# =========================================================================== #

class TestSmallPredicates(unittest.TestCase):
    def test_is_none_value(self):
        self.assertTrue(isNoneValue(None))
        self.assertTrue(isNoneValue("None"))
        self.assertTrue(isNoneValue(""))
        self.assertTrue(isNoneValue([]))
        self.assertTrue(isNoneValue(["None", ""]))
        self.assertTrue(isNoneValue({}))
        self.assertFalse(isNoneValue([2]))
        self.assertFalse(isNoneValue("x"))

    def test_is_null_value(self):
        self.assertTrue(isNullValue(u"NULL"))
        self.assertTrue(isNullValue(u"null"))
        self.assertFalse(isNullValue(u"foobar"))
        self.assertFalse(isNullValue(5))

    def test_is_num_pos_str_value(self):
        self.assertTrue(isNumPosStrValue(1))
        self.assertTrue(isNumPosStrValue("1"))
        self.assertFalse(isNumPosStrValue(0))
        self.assertFalse(isNumPosStrValue("-2"))
        self.assertFalse(isNumPosStrValue("100000000000000000000"))
        self.assertFalse(isNumPosStrValue("abc"))

    def test_is_number(self):
        self.assertTrue(isNumber(1))
        self.assertTrue(isNumber("0"))
        self.assertTrue(isNumber("3.14"))
        self.assertFalse(isNumber("foobar"))
        self.assertFalse(isNumber(None))

    def test_is_list_like(self):
        self.assertTrue(isListLike([1]))
        self.assertTrue(isListLike((1,)))
        self.assertTrue(isListLike(set([1])))
        self.assertFalse(isListLike("x"))
        self.assertFalse(isListLike(5))


class TestValueShaping(unittest.TestCase):
    def test_filter_pair_values(self):
        self.assertEqual(filterPairValues([[1, 2], [3], 1, [4, 5]]), [[1, 2], [4, 5]])
        self.assertEqual(filterPairValues(None), [])

    def test_filter_list_value(self):
        self.assertEqual(filterListValue(["users", "admins", "logs"], r"(users|admins)"),
                         ["users", "admins"])
        # non-list input returned unchanged
        self.assertEqual(filterListValue("notlist", r"x"), "notlist")
        # no regex returns input
        self.assertEqual(filterListValue(["a"], None), ["a"])

    def test_filter_none(self):
        self.assertEqual(filterNone([1, 2, "", None, 3, 0]), [1, 2, 3, 0])

    def test_filter_string_value(self):
        self.assertEqual(filterStringValue("wzydeadbeef0123#", r"[0-9a-f]"), "deadbeef0123")

    def test_un_arrayize_value(self):
        self.assertEqual(unArrayizeValue(["1"]), "1")
        self.assertEqual(unArrayizeValue("1"), "1")
        self.assertEqual(unArrayizeValue(["1", "2"]), "1")
        self.assertEqual(unArrayizeValue([["a", "b"], "c"]), "a")
        self.assertIsNone(unArrayizeValue([]))

    def test_flatten_value(self):
        self.assertEqual(list(flattenValue([["1"], [["2"], "3"]])), ["1", "2", "3"])

    def test_arrayize_value(self):
        self.assertEqual(arrayizeValue("1"), ["1"])
        self.assertEqual(arrayizeValue(["1"]), ["1"])

    def test_join_value(self):
        self.assertEqual(joinValue(["1", "2"]), "1,2")
        self.assertEqual(joinValue("1"), "1")
        self.assertEqual(joinValue(["1", None]), "1,None")


class TestZeroDepthAndSplit(unittest.TestCase):
    def test_zero_depth_search_skips_parens(self):
        expr = "SELECT (SELECT id FROM users WHERE 2>1) AS r FROM DUAL"
        idx = zeroDepthSearch(expr, " FROM ")
        # only the outer top-level FROM is found, not the one inside the subselect
        self.assertEqual(len(idx), 1)
        self.assertTrue(expr[idx[0]:].startswith(" FROM DUAL"))

    def test_zero_depth_search_ignores_quoted(self):
        expr = "a , 'b , c' , d"
        # commas inside the quoted literal are not reported
        self.assertEqual(len(zeroDepthSearch(expr, ",")), 2)

    def test_split_fields_basic(self):
        self.assertEqual(splitFields("foo, bar, max(foo, bar)"),
                         ["foo", "bar", "max(foo,bar)"])

    def test_split_fields_quoted(self):
        self.assertEqual(splitFields("a, 'b, c', d"), ["a", "'b, c'", "d"])

    def test_split_fields_custom_delimiter(self):
        self.assertEqual(splitFields("a; b; max(c; d)", delimiter=";"),
                         ["a", "b", "max(c;d)"])


class TestAliasToDbmsEnum(unittest.TestCase):
    def test_known_aliases(self):
        self.assertEqual(aliasToDbmsEnum("mssql"), DBMS.MSSQL)
        self.assertEqual(aliasToDbmsEnum("mysql"), DBMS.MYSQL)
        self.assertEqual(aliasToDbmsEnum("postgres"), DBMS.PGSQL)

    def test_unknown_alias_returns_none(self):
        self.assertIsNone(aliasToDbmsEnum("definitely_not_a_dbms"))

    def test_empty_returns_none(self):
        self.assertIsNone(aliasToDbmsEnum(""))


class TestGetPageWordSet(unittest.TestCase):
    def test_word_extraction(self):
        words = getPageWordSet(u"<html><title>foobar</title><body>test</body></html>")
        self.assertEqual(sorted(words), [u"foobar", u"test"])

    def test_non_string_returns_empty(self):
        self.assertEqual(getPageWordSet(None), set())


class TestNormalizeUnicode(unittest.TestCase):
    def test_accents_stripped(self):
        # normalizeUnicode collapses accented chars to their ASCII base
        self.assertEqual(normalizeUnicode(u"\xe9\xe8"), "ee")

    def test_plain_ascii_unchanged(self):
        self.assertEqual(normalizeUnicode(u"abc123"), "abc123")

    def test_none_returns_none(self):
        self.assertIsNone(normalizeUnicode(None))


class TestResetCookieJar(unittest.TestCase):
    """resetCookieJar's clear branch (conf.loadCookies falsy)."""

    def setUp(self):
        self._loadCookies = conf.loadCookies
        conf.loadCookies = None

    def tearDown(self):
        conf.loadCookies = self._loadCookies

    def test_clear_branch(self):
        try:
            from http.cookiejar import CookieJar
        except ImportError:  # Python 2
            from cookielib import CookieJar

        jar = CookieJar()
        cleared = {"called": False}

        class _Jar(object):
            def clear(self):
                cleared["called"] = True

        resetCookieJar(_Jar())
        self.assertTrue(cleared["called"])
        # also accepts a real jar without raising
        self.assertIsNone(resetCookieJar(jar))


# =========================================================================== #
# from tests/test_core_extra.py (common.py classes)
# =========================================================================== #

class TestCommonStringHelpers(unittest.TestCase):
    """Small pure string/list/regex/encoding helpers in lib/core/common.py."""

    def test_posix_to_nt_slashes(self):
        from lib.core.common import posixToNtSlashes
        self.assertEqual(posixToNtSlashes("C:/Windows"), "C:\\Windows")
        self.assertEqual(posixToNtSlashes("a/b/c"), "a\\b\\c")
        # falsy input returned unchanged
        self.assertEqual(posixToNtSlashes(""), "")
        self.assertIsNone(posixToNtSlashes(None))

    def test_nt_to_posix_slashes(self):
        from lib.core.common import ntToPosixSlashes
        self.assertEqual(ntToPosixSlashes("C:\\Windows"), "C:/Windows")
        self.assertEqual(ntToPosixSlashes("a\\b\\c"), "a/b/c")
        self.assertEqual(ntToPosixSlashes(""), "")

    def test_is_hex_encoded_string(self):
        from lib.core.common import isHexEncodedString
        self.assertTrue(isHexEncodedString("DEADBEEF"))
        self.assertTrue(isHexEncodedString("0x1234"))   # 'x' is allowed by the regex
        self.assertFalse(isHexEncodedString("test"))
        self.assertFalse(isHexEncodedString("12 34"))   # space breaks it

    def test_is_digit(self):
        from lib.core.common import isDigit
        self.assertTrue(isDigit("123456"))
        self.assertFalse(isDigit("3b3"))
        self.assertFalse(isDigit(u"\xb2"))              # superscript-2: str.isdigit() True, isDigit False
        self.assertFalse(isDigit(""))                   # empty -> no match
        self.assertFalse(isDigit(None))

    def test_sanitize_str(self):
        from lib.core.common import sanitizeStr
        self.assertEqual(sanitizeStr("foo\n\rbar"), "foo bar")
        self.assertEqual(sanitizeStr("a\r\nb"), "a b")
        self.assertEqual(sanitizeStr(None), "None")

    def test_filter_control_chars(self):
        from lib.core.common import filterControlChars
        self.assertEqual(filterControlChars("AND 1>(2+3)\n--"), "AND 1>(2+3) --")
        # custom replacement character
        self.assertEqual(filterControlChars("a\tb", replacement="_"), "a_b")

    def test_normalize_path(self):
        from lib.core.common import normalizePath
        self.assertEqual(normalizePath("//var///log/apache.log"), "/var/log/apache.log")
        self.assertEqual(normalizePath("/a/b/../c"), "/a/c")

    def test_directory_path(self):
        from lib.core.common import directoryPath
        self.assertEqual(directoryPath("/var/log/apache.log"), "/var/log")
        # no extension -> returned unchanged
        self.assertEqual(directoryPath("/var/log"), "/var/log")

    def test_longest_common_prefix(self):
        from lib.core.common import longestCommonPrefix
        self.assertEqual(longestCommonPrefix("foobar", "fobar"), "fo")
        self.assertEqual(longestCommonPrefix("abc", "abd", "abe"), "ab")
        # single sequence returned verbatim
        self.assertEqual(longestCommonPrefix("only"), "only")

    def test_first_not_none(self):
        from lib.core.common import firstNotNone
        self.assertEqual(firstNotNone(None, None, 1, 2, 3), 1)
        self.assertEqual(firstNotNone(None, 0), 0)      # 0 is not None
        self.assertIsNone(firstNotNone(None, None))

    def test_decode_string_escape(self):
        from lib.core.common import decodeStringEscape
        self.assertEqual(decodeStringEscape("a\\tb"), "a\tb")
        self.assertEqual(decodeStringEscape("a\\nb"), "a\nb")
        # no backslash -> unchanged
        self.assertEqual(decodeStringEscape("plain"), "plain")

    def test_encode_string_escape(self):
        from lib.core.common import encodeStringEscape
        self.assertEqual(encodeStringEscape("a\tb"), "a\\tb")
        self.assertEqual(encodeStringEscape("a\nb"), "a\\nb")
        self.assertEqual(encodeStringEscape("plain"), "plain")

    def test_decode_encode_string_escape_roundtrip(self):
        from lib.core.common import decodeStringEscape, encodeStringEscape
        self.assertEqual(decodeStringEscape(encodeStringEscape("x\ty\nz")), "x\ty\nz")

    def test_escape_json_value(self):
        from lib.core.common import escapeJsonValue
        # newline gets escaped (literal '\n' becomes the two chars backslash+n)
        self.assertNotIn("\n", escapeJsonValue("foo\nbar"))
        self.assertIn("\\n", escapeJsonValue("foo\nbar"))
        # tab gets escaped to '\t'
        self.assertIn("\\t", escapeJsonValue("foo\tbar"))
        # quote and backslash escaped
        self.assertEqual(escapeJsonValue('a"b'), 'a\\"b')
        self.assertEqual(escapeJsonValue("a\\b"), "a\\\\b")
        # ordinary characters untouched
        self.assertEqual(escapeJsonValue("plain text"), "plain text")

    def test_clean_query(self):
        from lib.core.common import cleanQuery
        self.assertEqual(cleanQuery("select id from users"), "SELECT id FROM users")
        # already-uppercase keywords stay; identifiers untouched
        self.assertEqual(cleanQuery("SELECT a FROM t"), "SELECT a FROM t")

    def test_json_minimize_canonical(self):
        from lib.core.common import jsonMinimize
        # key order / whitespace independence
        self.assertEqual(jsonMinimize('{"b": 2, "a": 1}'), jsonMinimize('{"a":1,  "b":2}'))
        # nested leaf path
        self.assertEqual(jsonMinimize('{"a": {"b": 1}}'), ".a.b=1")
        # empty object
        self.assertEqual(jsonMinimize("{}"), "")
        # not parseable -> None (and only None)
        self.assertIsNone(jsonMinimize("not json"))

    def test_json_minimize_array_length_registers(self):
        from lib.core.common import jsonMinimize
        # array length change must perturb the projection
        self.assertNotEqual(jsonMinimize('{"a": [1, 2]}'), jsonMinimize('{"a": [1, 2, 3]}'))

    def test_list_to_str_value(self):
        from lib.core.common import listToStrValue
        self.assertEqual(listToStrValue([1, 2, 3]), "1, 2, 3")
        # set/tuple/generator normalized via list first
        self.assertEqual(listToStrValue((1, 2)), "1, 2")
        # non-list passes through
        self.assertEqual(listToStrValue("abc"), "abc")

    def test_intersect(self):
        from lib.core.common import intersect
        self.assertEqual(intersect([1, 2, 3], set([1, 3])), [1, 3])
        # order follows containerA
        self.assertEqual(intersect([3, 2, 1], [1, 2]), [2, 1])
        # case-insensitive option
        self.assertEqual(intersect(["FOO", "bar"], ["foo"], lowerCase=True), ["foo"])

    def test_priority_sort_columns(self):
        from lib.core.common import prioritySortColumns
        # 'id'-containing columns first, then by ascending length
        self.assertEqual(
            prioritySortColumns(["password", "userid", "name", "id"]),
            ["id", "userid", "name", "password"],
        )

    def test_safe_variable_naming(self):
        from lib.core.common import safeVariableNaming
        self.assertEqual(safeVariableNaming("class.id"), "EVAL_636c6173732e6964")
        # plain identifier left untouched
        self.assertEqual(safeVariableNaming("foobar"), "foobar")

    def test_unsafe_variable_naming(self):
        from lib.core.common import unsafeVariableNaming
        self.assertEqual(unsafeVariableNaming("EVAL_636c6173732e6964"), "class.id")
        self.assertEqual(unsafeVariableNaming("foobar"), "foobar")

    def test_variable_naming_roundtrip(self):
        from lib.core.common import safeVariableNaming, unsafeVariableNaming
        self.assertEqual(unsafeVariableNaming(safeVariableNaming("a-b")), "a-b")

    def test_average(self):
        from lib.core.common import average
        self.assertAlmostEqual(average([0.9, 0.9, 0.9, 1.0, 0.8, 0.9]), 0.9, places=6)
        self.assertEqual(average([2, 4]), 3.0)
        self.assertIsNone(average([]))

    def test_stdev(self):
        from lib.core.common import stdev
        self.assertEqual("%.3f" % stdev([0.9, 0.9, 0.9, 1.0, 0.8, 0.9]), "0.063")
        # fewer than 2 values -> None
        self.assertIsNone(stdev([1.0]))
        self.assertIsNone(stdev([]))


class TestCommonSafeCompare(unittest.TestCase):
    """Constant-time / checksum helpers."""

    def test_safe_compare_strings(self):
        from lib.core.common import safeCompareStrings
        self.assertTrue(safeCompareStrings("test", "test"))
        self.assertFalse(safeCompareStrings("test1", "test2"))
        self.assertFalse(safeCompareStrings("test", None))
        # both None compares equal (a == b path)
        self.assertTrue(safeCompareStrings(None, None))

    def test_safe_cs_value(self):
        from lib.core.common import safeCSValue
        # ensure deterministic delimiter
        old = conf.get("csvDel")
        conf.csvDel = defaults.csvDel
        try:
            self.assertEqual(safeCSValue("foo, bar"), '"foo, bar"')
            self.assertEqual(safeCSValue("foobar"), "foobar")
            self.assertEqual(safeCSValue("foo\rbar"), '"foo\rbar"')
            self.assertEqual(safeCSValue('foo"bar'), '"foo""bar"')
        finally:
            conf.csvDel = old


class TestCommonSafeExString(unittest.TestCase):
    def test_sqlmap_exception_message(self):
        from lib.core.common import getSafeExString
        from lib.core.exception import SqlmapBaseException
        self.assertEqual(getSafeExString(SqlmapBaseException("foobar")), "foobar")

    def test_oserror_prefixed_with_type(self):
        from lib.core.common import getSafeExString
        self.assertEqual(getSafeExString(OSError(0, "foobar")), "OSError: foobar")

    def test_generic_value_error(self):
        from lib.core.common import getSafeExString
        self.assertEqual(getSafeExString(ValueError("bad input")), "ValueError: bad input")


class TestCommonHostHeader(unittest.TestCase):
    def test_plain_host(self):
        from lib.core.common import getHostHeader
        self.assertEqual(getHostHeader("http://www.target.com/vuln.php?id=1"), "www.target.com")

    def test_default_port_stripped(self):
        from lib.core.common import getHostHeader
        self.assertEqual(getHostHeader("http://www.target.com:80/x"), "www.target.com")
        self.assertEqual(getHostHeader("https://www.target.com:443/x"), "www.target.com")

    def test_nondefault_port_kept(self):
        from lib.core.common import getHostHeader
        self.assertEqual(getHostHeader("http://www.target.com:8080/x"), "www.target.com:8080")

    def test_ipv6_brackets(self):
        from lib.core.common import getHostHeader
        self.assertEqual(getHostHeader("http://[::1]:8080/vuln.php?id=1"), "[::1]:8080")
        self.assertEqual(getHostHeader("http://[::1]/vuln.php?id=1"), "[::1]")


class TestCommonCheckSameHost(unittest.TestCase):
    def test_same_host(self):
        from lib.core.common import checkSameHost
        self.assertTrue(checkSameHost(
            "http://www.target.com/page1.php?id=1",
            "http://www.target.com/images/page2.php",
        ))

    def test_different_host(self):
        from lib.core.common import checkSameHost
        self.assertFalse(checkSameHost(
            "http://www.target.com/page1.php?id=1",
            "http://www.target2.com/images/page2.php",
        ))

    def test_www_prefix_ignored(self):
        from lib.core.common import checkSameHost
        # leading 'www.' is stripped before comparison
        self.assertTrue(checkSameHost("http://www.target.com/a", "http://target.com/b"))

    def test_single_url_true_and_empty_none(self):
        from lib.core.common import checkSameHost
        self.assertTrue(checkSameHost("http://only.com/a"))
        self.assertIsNone(checkSameHost())


class TestCommonUrldecode(unittest.TestCase):
    def test_convall_true(self):
        from lib.core.common import urldecode
        self.assertEqual(urldecode("AND%201%3E%282%2B3%29%23", convall=True), "AND 1>(2+3)#")

    def test_convall_false_keeps_unsafe(self):
        from lib.core.common import urldecode
        # %2B (plus) is in the default 'unsafe' set so it stays encoded when convall=False
        self.assertEqual(urldecode("AND%201%3E%282%2B3%29%23", convall=False), "AND 1>(2%2B3)#")

    def test_bytes_input(self):
        from lib.core.common import urldecode
        self.assertEqual(urldecode(b"AND%201%3E%282%2B3%29%23", convall=False), "AND 1>(2%2B3)#")

    def test_spaceplus(self):
        from lib.core.common import urldecode
        # with spaceplus the '+' becomes a space
        self.assertEqual(urldecode("a+b", convall=False, spaceplus=True), "a b")
        # without spaceplus the '+' stays
        self.assertEqual(urldecode("a+b", convall=False, spaceplus=False), "a+b")


class TestCommonChunkSplit(unittest.TestCase):
    def test_chunk_split_post_data(self):
        import random
        from lib.core.common import chunkSplitPostData
        from lib.core.patch import unisonRandom
        # The pinned docstring value is produced under sqlmap's cross-version PRNG; install it
        # (then restore the stdlib functions) so the expectation is deterministic here too.
        _saved = (random.choice, random.randint, random.sample, random.seed)
        unisonRandom()
        try:
            random.seed(0)
            expected = ('5;4Xe90\r\nSELEC\r\n3;irWlc\r\nT u\r\n1;eT4zO\r\ns\r\n'
                        '5;YB4hM\r\nernam\r\n9;2pUD8\r\ne,passwor\r\n3;mp07y\r\nd F\r\n'
                        '5;8RKXi\r\nROM u\r\n4;MvMhO\r\nsers\r\n0\r\n\r\n')
            self.assertEqual(chunkSplitPostData("SELECT username,password FROM users"), expected)
        finally:
            random.choice, random.randint, random.sample, random.seed = _saved

    def test_chunk_split_terminator(self):
        import random
        from lib.core.common import chunkSplitPostData
        random.seed(123)
        # regardless of content, the chunked stream must end with the zero-length terminator
        self.assertTrue(chunkSplitPostData("abc").endswith("0\r\n\r\n"))


class TestCommonDecodeIntToUnicode(unittest.TestCase):
    def tearDown(self):
        set_dbms(None)

    def test_basic_ascii(self):
        from lib.core.common import decodeIntToUnicode
        self.assertEqual(decodeIntToUnicode(35), "#")
        self.assertEqual(decodeIntToUnicode(64), "@")
        self.assertEqual(decodeIntToUnicode(65), "A")

    def test_non_int_passthrough(self):
        from lib.core.common import decodeIntToUnicode
        # non-int is returned unchanged
        self.assertEqual(decodeIntToUnicode("x"), "x")

    def test_pgsql_high_codepoint(self):
        from lib.core.common import decodeIntToUnicode
        set_dbms(DBMS.PGSQL)
        # value > 255 on PGSQL takes the _unichr(value) branch
        self.assertEqual(decodeIntToUnicode(0x2122), u"\u2122")


class TestCommonDecodeDbmsHex(unittest.TestCase):
    def setUp(self):
        self._old_binary = kb.binaryField
        kb.binaryField = False

    def tearDown(self):
        kb.binaryField = self._old_binary
        set_dbms(None)

    def test_plain_hex(self):
        from lib.core.common import decodeDbmsHexValue
        self.assertEqual(decodeDbmsHexValue("3132332031"), u"123 1")

    def test_odd_length_appends_question_mark(self):
        from lib.core.common import decodeDbmsHexValue
        self.assertEqual(decodeDbmsHexValue("313233203"), u"123 ?")

    def test_list_input(self):
        from lib.core.common import decodeDbmsHexValue
        self.assertEqual(decodeDbmsHexValue(["0x31", "0x32"]), [u"1", u"2"])

    def test_non_hex_passthrough(self):
        from lib.core.common import decodeDbmsHexValue
        self.assertEqual(decodeDbmsHexValue("5.1.41"), u"5.1.41")


class TestCommonUnsafeSQLIdentificator(unittest.TestCase):
    def tearDown(self):
        set_dbms(None)

    def test_mssql_brackets(self):
        from lib.core.common import unsafeSQLIdentificatorNaming
        from lib.core.common import getText
        set_dbms(DBMS.MSSQL)
        self.assertEqual(getText(unsafeSQLIdentificatorNaming("[begin]")), "begin")
        self.assertEqual(getText(unsafeSQLIdentificatorNaming("foobar")), "foobar")

    def test_mysql_backticks(self):
        from lib.core.common import unsafeSQLIdentificatorNaming, getText
        set_dbms(DBMS.MYSQL)
        self.assertEqual(getText(unsafeSQLIdentificatorNaming("`col`")), "col")

    def test_oracle_uppercases(self):
        from lib.core.common import unsafeSQLIdentificatorNaming, getText
        set_dbms(DBMS.ORACLE)
        # Oracle strips double quotes and uppercases
        self.assertEqual(getText(unsafeSQLIdentificatorNaming('"name"')), "NAME")


class TestCommonParseSqliteSchema(unittest.TestCase):
    def setUp(self):
        self._old_cached = kb.data.get("cachedColumns")
        self._old_db = conf.db
        self._old_tbl = conf.tbl
        kb.data.cachedColumns = {}
        conf.db = "SQLITE_MASTER"
        conf.tbl = "users"

    def tearDown(self):
        kb.data.cachedColumns = self._old_cached
        conf.db = self._old_db
        conf.tbl = self._old_tbl

    def test_simple_schema(self):
        from lib.core.common import parseSqliteTableSchema
        self.assertTrue(parseSqliteTableSchema(
            "CREATE TABLE users(\n\t\tid INTEGER,\n\t\tname TEXT\n);"))
        cols = kb.data.cachedColumns[conf.db][conf.tbl]
        self.assertEqual(tuple(cols.items()), (("id", "INTEGER"), ("name", "TEXT")))

    def test_constraints_skipped(self):
        from lib.core.common import parseSqliteTableSchema
        self.assertTrue(parseSqliteTableSchema(
            "CREATE TABLE suppliers(\n\tsupplier_id INTEGER PRIMARY KEY DESC,\n\tname TEXT NOT NULL\n);"))
        cols = kb.data.cachedColumns[conf.db][conf.tbl]
        self.assertEqual(tuple(cols.items()), (("supplier_id", "INTEGER"), ("name", "TEXT")))


# =========================================================================== #
# from tests/test_core_final.py (common.py classes)
# =========================================================================== #

class TestCommonPureHelpers(unittest.TestCase):
    """Pure string/encoding/list/regex helpers from lib/core/common.py."""

    def test_boldify_message_marks_known_pattern(self):
        self.assertEqual(
            boldifyMessage("GET parameter id is not injectable", istty=True),
            "\x1b[1mGET parameter id is not injectable\x1b[0m",
        )

    def test_boldify_message_leaves_plain_unchanged(self):
        self.assertEqual(boldifyMessage("just a plain message", istty=True), "just a plain message")

    def test_calculate_delta_seconds_from_epoch(self):
        self.assertGreater(calculateDeltaSeconds(0), 1151721660)

    def test_calculate_delta_seconds_nonnegative(self):
        import time as _time
        self.assertGreaterEqual(calculateDeltaSeconds(_time.time()), 0.0)

    def test_common_finder_only_returns_longest_common_prefix(self):
        self.assertEqual(commonFinderOnly("abcd", ["abcdefg", "foobar", "abcde"]), "abcde")

    def test_enum_value_to_name_lookup_hit(self):
        self.assertEqual(enumValueToNameLookup(SORT_ORDER, SORT_ORDER.LAST), "LAST")

    def test_enum_value_to_name_lookup_miss(self):
        self.assertIsNone(enumValueToNameLookup(SORT_ORDER, -987654321))

    def test_file_path_to_safe_string(self):
        self.assertEqual(filePathToSafeString("C:/Windows/system32"), "C__Windows_system32")

    def test_file_path_to_safe_string_spaces_backslashes(self):
        self.assertEqual(filePathToSafeString("a b\\c:d"), "a_b_c_d")

    def test_is_windows_drive_letter_path_true(self):
        self.assertTrue(isWindowsDriveLetterPath("C:\\boot.ini"))

    def test_is_windows_drive_letter_path_false(self):
        self.assertFalse(isWindowsDriveLetterPath("/var/log/apache.log"))

    def test_clean_replace_unicode_list(self):
        self.assertEqual(cleanReplaceUnicode(["a", "b"]), ["a", "b"])

    def test_clean_replace_unicode_scalar(self):
        self.assertEqual(cleanReplaceUnicode(u"plain"), u"plain")

    def test_trim_alpha_num(self):
        self.assertEqual(trimAlphaNum("AND 1>(2+3)-- foobar"), " 1>(2+3)-- ")

    def test_trim_alpha_num_all_alnum(self):
        self.assertEqual(trimAlphaNum("abc123"), "")

    def test_trim_alpha_num_empty(self):
        self.assertEqual(trimAlphaNum(""), "")

    def test_list_to_str_value_list(self):
        self.assertEqual(listToStrValue([1, 2, 3]), "1, 2, 3")

    def test_list_to_str_value_tuple(self):
        self.assertEqual(listToStrValue((4, 5)), "4, 5")

    def test_list_to_str_value_scalar(self):
        self.assertEqual(listToStrValue("foo"), "foo")

    def test_intersect_lists(self):
        self.assertEqual(intersect([1, 2, 3], set([1, 3])), [1, 3])

    def test_intersect_lowercase(self):
        self.assertEqual(intersect(["A", "B"], ["a"], lowerCase=True), ["a"])

    def test_intersect_empty(self):
        self.assertEqual(intersect([], [1, 2]), [])

    def test_apply_function_recursively(self):
        self.assertEqual(
            applyFunctionRecursively([1, 2, [3, -9]], lambda _: _ > 0),
            [True, True, [True, False]],
        )

    def test_apply_function_recursively_scalar(self):
        self.assertEqual(applyFunctionRecursively(5, lambda _: _ + 1), 6)


class TestCommonRegexAndPage(unittest.TestCase):
    """Regex / page-content extraction helpers."""

    def test_extract_regex_result_hit(self):
        self.assertEqual(extractRegexResult(r"a(?P<result>[^g]+)g", "abcdefg"), "bcdef")

    def test_extract_regex_result_no_match(self):
        self.assertIsNone(extractRegexResult(r"a(?P<result>[^g]+)g", "xyz"))

    def test_extract_regex_result_no_result_group(self):
        self.assertIsNone(extractRegexResult(r"plain", "plain"))

    def test_extract_regex_result_empty_content(self):
        self.assertIsNone(extractRegexResult(r"a(?P<result>.)b", ""))

    def test_extract_text_tag_content(self):
        self.assertEqual(
            extractTextTagContent("<html><head><title>Title</title></head><body><pre>foobar</pre></body></html>"),
            ["Title", "foobar"],
        )

    def test_extract_text_tag_content_empty(self):
        self.assertEqual(extractTextTagContent(""), [])

    def test_get_filtered_page_content(self):
        self.assertEqual(
            getFilteredPageContent(u"<html><title>foobar</title><body>test</body></html>"),
            "foobar test",
        )

    def test_get_filtered_page_content_drops_script(self):
        page = u"<html><script>var x=1;</script><body>hello</body></html>"
        self.assertNotIn("var x", getFilteredPageContent(page))
        self.assertIn("hello", getFilteredPageContent(page))

    def test_get_filtered_page_content_nonstring_passthrough(self):
        self.assertEqual(getFilteredPageContent(None), None)

    def test_extract_error_message_oracle(self):
        page = (u"<html><title>Test</title>\n<b>Warning</b>: oci_parse() "
                u"[function.oci-parse]: ORA-01756: quoted string not properly "
                u"terminated<br><p>Only a test page</p></html>")
        self.assertEqual(
            getText(extractErrorMessage(page)),
            "oci_parse() [function.oci-parse]: ORA-01756: quoted string not properly terminated",
        )

    def test_extract_error_message_none_for_plain(self):
        self.assertIsNone(extractErrorMessage("Warning: This is only a dummy foobar test"))

    def test_extract_error_message_non_string(self):
        self.assertIsNone(extractErrorMessage(None))

    def test_find_multipart_post_boundary(self):
        post = ("-----------------------------9051914041544843365972754266\n"
                "Content-Disposition: form-data; name=text\n\ndefault")
        self.assertEqual(findMultipartPostBoundary(post), "9051914041544843365972754266")

    def test_find_multipart_post_boundary_none(self):
        self.assertIsNone(findMultipartPostBoundary(""))


class TestCommonHeadersAndExpected(unittest.TestCase):

    def test_get_header_case_insensitive(self):
        self.assertEqual(getHeader({"Foo": "bar"}, "foo"), "bar")

    def test_get_header_missing(self):
        self.assertIsNone(getHeader({"Foo": "bar"}, "x"))

    def test_get_header_empty_dict(self):
        self.assertIsNone(getHeader({}, "anything"))

    def test_get_request_header_hit(self):
        self.assertEqual(getText(getRequestHeader(_FakeRequest({"FOO": "BAR"}), "foo")), "BAR")

    def test_get_request_header_miss(self):
        self.assertIsNone(getRequestHeader(_FakeRequest({"FOO": "BAR"}), "missing"))

    def test_extract_expected_value_bool_true(self):
        self.assertIs(extractExpectedValue(["1"], EXPECTED.BOOL), True)

    def test_extract_expected_value_bool_false(self):
        self.assertIs(extractExpectedValue(["0"], EXPECTED.BOOL), False)

    def test_extract_expected_value_bool_word(self):
        self.assertIs(extractExpectedValue(["true"], EXPECTED.BOOL), True)
        self.assertIs(extractExpectedValue(["false"], EXPECTED.BOOL), False)

    def test_extract_expected_value_int(self):
        self.assertEqual(extractExpectedValue("5", EXPECTED.INT), 5)

    def test_extract_expected_value_int_invalid(self):
        self.assertIsNone(extractExpectedValue(u"7\xb9645", EXPECTED.INT))

    def test_extract_expected_value_no_expected(self):
        self.assertEqual(extractExpectedValue("foo", None), "foo")


class TestParseJsonAndHash(unittest.TestCase):

    def test_parse_json_double_quotes(self):
        self.assertEqual(parseJson('{"id":1}')["id"], 1)

    def test_parse_json_single_quotes(self):
        self.assertEqual(parseJson("{'id':1, 'foo':[2,3,4]}")["id"], 1)

    def test_parse_json_not_json(self):
        self.assertIsNone(parseJson("this is not json"))

    def test_parse_password_hash_mssql(self):
        saved = kb.forcedDbms
        try:
            kb.forcedDbms = DBMS.MSSQL
            result = parsePasswordHash("0x01004086ceb60c90646a8ab9889fe3ed8e5c150b5460ece8425a")
            self.assertIn("salt: 4086ceb6", result)
            self.assertIn("header: 0x0100", result)
        finally:
            kb.forcedDbms = saved

    def test_parse_password_hash_none(self):
        self.assertEqual(parsePasswordHash(None), NULL)

    def test_parse_password_hash_blank(self):
        self.assertEqual(parsePasswordHash(" "), NULL)


class TestSerializeAndTechnique(unittest.TestCase):

    def test_serialize_roundtrip(self):
        self.assertEqual(unserializeObject(serializeObject([1, 2, 3])), [1, 2, 3])

    def test_serialize_object_is_str(self):
        self.assertIsInstance(serializeObject([1, 2, ("a", "b")]), str)

    def test_unserialize_none(self):
        self.assertIsNone(unserializeObject(None))

    def test_set_get_technique_thread_local(self):
        saved = getTechnique()
        try:
            setTechnique(5)
            self.assertEqual(getTechnique(), 5)
        finally:
            setTechnique(saved)

    def test_get_technique_falls_back_to_kb(self):
        saved_thread = getTechnique()
        saved_kb = kb.get("technique")
        try:
            setTechnique(None)
            kb.technique = 7
            self.assertEqual(getTechnique(), 7)
        finally:
            setTechnique(saved_thread)
            kb.technique = saved_kb


class TestRemovePostHint(unittest.TestCase):

    def test_removes_known_prefix(self):
        self.assertEqual(removePostHintPrefix("JSON id"), "id")

    def test_no_prefix_unchanged(self):
        self.assertEqual(removePostHintPrefix("id"), "id")


class TestFileHelpers(unittest.TestCase):

    def test_check_file_existing(self):
        self.assertTrue(checkFile(__file__))

    def test_check_file_missing_no_raise(self):
        self.assertFalse(checkFile("/no/such/path_xyz_123", raiseOnError=False))

    def test_check_file_missing_raises(self):
        with self.assertRaises(SqlmapSystemException):
            checkFile("/no/such/path_xyz_123", raiseOnError=True)

    def test_is_zip_file_wordlist(self):
        # paths.WORDLIST is a zip-compressed wordlist shipped with sqlmap
        self.assertTrue(isZipFile(paths.WORDLIST))

    def test_is_zip_file_plain_text(self):
        self.assertFalse(isZipFile(paths.SQL_KEYWORDS))

    def test_safe_filepath_encode_ascii_passthrough(self):
        # On Python 3 the function returns the value unchanged for str input
        self.assertEqual(safeFilepathEncode("/tmp/x"), "/tmp/x")

    def test_safe_expand_user_basename_preserved(self):
        self.assertIn(os.path.basename(__file__), safeExpandUser(__file__))


class TestCheckOldOptions(unittest.TestCase):

    def test_no_old_options_is_noop(self):
        # Returns None and does not raise when no deprecated options are present
        self.assertIsNone(checkOldOptions(["-u", "http://test.invalid/?id=1", "--banner"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
