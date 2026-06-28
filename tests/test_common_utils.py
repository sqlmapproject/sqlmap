#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Pure / near-pure helpers in lib/core/common.py.

These cover the request/parameter parsing, charset construction, limit-range
generation, safe string formatting, URL encoding, UNION page parsing, target
URL/direct-connection parsing and SQL identifier quoting. They are exercised
in isolation (no network, no DBMS, no filesystem mutation); any function that
reads/writes global conf/kb state has that state saved and restored around the
call so test ordering stays irrelevant.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap, set_dbms
bootstrap()

from lib.core.common import (
    paramToDict,
    getCharset,
    getLimitRange,
    parseUnionPage,
    safeStringFormat,
    urlencode,
    parseTargetUrl,
    parseTargetDirect,
    safeSQLIdentificatorNaming,
    getPartRun,
    getText,
)
from lib.core.data import kb, conf
from lib.core.enums import PLACE, CHARSET_TYPE, DBMS


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
