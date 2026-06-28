#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Additional REAL unit coverage for genuinely-uncovered PURE functions in:

  * lib/core/common.py
  * lib/core/option.py
  * lib/core/agent.py
  * lib/request/basic.py

Every test asserts a concrete, independently-reasoned known-correct value that
would FAIL if the function under test regressed. No isinstance-only checks, no
tautologies, no swallowed exceptions.

Functions targeted here are deliberately DIFFERENT from those already exercised
by tests/test_common_utils.py, test_common_parsers.py, test_core_more.py,
test_core_final.py, test_option_setup.py, test_option_more.py, test_agent.py,
test_agent_dialects.py, test_decodepage.py and test_charset.py.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests._testutils import bootstrap, set_dbms

bootstrap()

from lib.core.data import conf, kb
from lib.core.defaults import defaults
from lib.core.common import Backend
from lib.core.enums import DBMS


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
        self.assertEqual(decodeIntToUnicode(0x2122), u"™")


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


class TestAgentPure(unittest.TestCase):
    """Pure agent.py methods independent of full injection state."""

    @classmethod
    def setUpClass(cls):
        from lib.core.agent import agent
        cls.agent = agent

    def tearDown(self):
        set_dbms(None)

    def test_get_comment_present(self):
        from lib.core.datatype import AttribDict
        request = AttribDict()
        request.comment = "-- foo"
        self.assertEqual(self.agent.getComment(request), "-- foo")

    def test_get_comment_absent(self):
        from lib.core.datatype import AttribDict
        request = AttribDict()
        self.assertEqual(self.agent.getComment(request), "")

    def test_add_payload_delimiters(self):
        from lib.core.settings import PAYLOAD_DELIMITER
        value = "1 AND 1=1"
        result = self.agent.addPayloadDelimiters(value)
        self.assertEqual(result, "%s%s%s" % (PAYLOAD_DELIMITER, value, PAYLOAD_DELIMITER))
        # falsy value returned unchanged
        self.assertEqual(self.agent.addPayloadDelimiters(""), "")

    def test_remove_payload_delimiters_roundtrip(self):
        self.assertEqual(
            self.agent.removePayloadDelimiters(self.agent.addPayloadDelimiters("1 AND 1=1")),
            "1 AND 1=1",
        )

    def test_extract_payload(self):
        wrapped = "prefix" + self.agent.addPayloadDelimiters("1 AND 1=1") + "suffix"
        self.assertEqual(self.agent.extractPayload(wrapped), "1 AND 1=1")

    def test_replace_payload(self):
        wrapped = "prefix" + self.agent.addPayloadDelimiters("OLD") + "suffix"
        replaced = self.agent.replacePayload(wrapped, "NEW")
        self.assertEqual(self.agent.extractPayload(replaced), "NEW")
        # surrounding text preserved
        self.assertTrue(replaced.startswith("prefix"))
        self.assertTrue(replaced.endswith("suffix"))

    def test_simple_concatenate_mysql(self):
        set_dbms(DBMS.MYSQL)
        # MySQL concatenate query template is 'CONCAT(%s,%s)'
        self.assertEqual(self.agent.simpleConcatenate("a", "b"), "CONCAT(a,b)")

    def test_hex_convert_field_mysql(self):
        set_dbms(DBMS.MYSQL)
        # MySQL hex template is 'HEX(%s)'
        self.assertEqual(self.agent.hexConvertField("col"), "HEX(col)")

    def test_get_fields_select_from(self):
        set_dbms(DBMS.MYSQL)
        result = self.agent.getFields("SELECT a, b FROM users")
        fieldsToCastList = result[5]
        fieldsToCastStr = result[6]
        self.assertEqual(fieldsToCastStr, "a, b")
        self.assertEqual(fieldsToCastList, ["a", "b"])

    def test_get_fields_no_from(self):
        set_dbms(DBMS.MYSQL)
        # a bare SELECT without FROM -> fieldsSelectFrom is None, casts the whole select list
        result = self.agent.getFields("SELECT 1")
        fieldsSelectFrom = result[0]
        self.assertIsNone(fieldsSelectFrom)
        self.assertEqual(result[6], "1")


class TestAgentWhereQuery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from lib.core.agent import agent
        cls.agent = agent

    def setUp(self):
        self._old_dumpWhere = conf.dumpWhere
        self._old_tbl = conf.tbl
        conf.tbl = None

    def tearDown(self):
        conf.dumpWhere = self._old_dumpWhere
        conf.tbl = self._old_tbl
        set_dbms(None)

    def test_no_dumpwhere_passthrough(self):
        conf.dumpWhere = None
        query = "SELECT a FROM t"
        self.assertEqual(self.agent.whereQuery(query), query)

    def test_appends_where_clause(self):
        set_dbms(DBMS.MYSQL)
        conf.dumpWhere = "id>0"
        # no existing WHERE -> appends ' WHERE id>0'
        self.assertEqual(self.agent.whereQuery("SELECT a FROM t"), "SELECT a FROM t WHERE id>0")

    def test_and_when_where_present(self):
        set_dbms(DBMS.MYSQL)
        conf.dumpWhere = "id>0"
        # existing WHERE -> appended with AND
        self.assertEqual(
            self.agent.whereQuery("SELECT a FROM t WHERE x=1"),
            "SELECT a FROM t WHERE x=1 AND id>0",
        )

    def test_splices_before_order_by(self):
        set_dbms(DBMS.MYSQL)
        conf.dumpWhere = "id>0"
        # WHERE must be spliced before the trailing ORDER BY suffix
        self.assertEqual(
            self.agent.whereQuery("SELECT a FROM t ORDER BY a"),
            "SELECT a FROM t WHERE id>0 ORDER BY a",
        )


class TestBasicHeuristicCharEncoding(unittest.TestCase):
    def test_ascii(self):
        from lib.request.basic import getHeuristicCharEncoding
        self.assertEqual(getHeuristicCharEncoding(b"<html></html>"), "ascii")

    def test_cache_hit_returns_same(self):
        from lib.request.basic import getHeuristicCharEncoding
        page = b"<html>hello world</html>"
        first = getHeuristicCharEncoding(page)
        # second call for identical page must come back identical (and from cache)
        self.assertEqual(getHeuristicCharEncoding(page), first)
        key = (len(page), hash(page))
        self.assertEqual(kb.cache.encoding.get(key), first)


class TestBasicDecodePage(unittest.TestCase):
    """decodePage charset + HTML-entity decoding branches."""

    def setUp(self):
        self._old_encoding = conf.encoding
        self._old_null = conf.nullConnection
        conf.nullConnection = False

    def tearDown(self):
        conf.encoding = self._old_encoding
        conf.nullConnection = self._old_null

    def test_html_entity_amp(self):
        from lib.request.basic import decodePage
        from lib.core.common import getText
        conf.encoding = None
        self.assertEqual(
            getText(decodePage(b"<html>foo&amp;bar</html>", None, "text/html; charset=utf-8")),
            "<html>foo&bar</html>",
        )

    def test_numeric_hex_entity_tab(self):
        from lib.request.basic import decodePage
        from lib.core.common import getText
        conf.encoding = None
        self.assertEqual(getText(decodePage(b"&#x9;", None, "text/html; charset=utf-8")), "\t")

    def test_numeric_hex_entity_letter(self):
        from lib.request.basic import decodePage
        from lib.core.common import getText
        conf.encoding = None
        self.assertEqual(getText(decodePage(b"&#x4A;", None, "text/html; charset=utf-8")), "J")

    def test_unicode_entity(self):
        from lib.request.basic import decodePage
        conf.encoding = None
        self.assertEqual(decodePage(b"&#x2122;", None, "text/html; charset=utf-8"), u"™")

    def test_empty_page(self):
        from lib.request.basic import decodePage
        from lib.core.common import getText
        # empty page short-circuits to getUnicode(page)
        self.assertEqual(getText(decodePage(b"", None, "text/html")), "")


class TestOptionSetPrefixSuffix(unittest.TestCase):
    """_setPrefixSuffix boundary construction (pure conf-mutation, no I/O)."""

    def setUp(self):
        self._saved = {k: conf.get(k) for k in ("prefix", "suffix", "boundaries")}

    def tearDown(self):
        for k, v in self._saved.items():
            conf[k] = v

    def _run(self, prefix, suffix):
        from lib.core.option import _setPrefixSuffix
        conf.prefix = prefix
        conf.suffix = suffix
        conf.boundaries = None
        _setPrefixSuffix()
        return conf.boundaries

    def test_none_no_boundary(self):
        # when either prefix or suffix is None, no boundary is created
        self.assertIsNone(self._run(None, None))

    def test_single_quote_ptype(self):
        boundaries = self._run("' AND ", "'")
        self.assertEqual(len(boundaries), 1)
        b = boundaries[0]
        self.assertEqual(b.prefix, "' AND ")
        self.assertEqual(b.suffix, "'")
        self.assertEqual(b.ptype, 2)         # single-quote, no LIKE
        self.assertEqual(b.level, 1)
        self.assertEqual(b.clause, [0])

    def test_double_quote_ptype(self):
        boundaries = self._run('" AND ', '"')
        self.assertEqual(boundaries[0].ptype, 4)   # double-quote, no LIKE

    def test_numeric_ptype(self):
        boundaries = self._run(" AND ", "")
        self.assertEqual(boundaries[0].ptype, 1)   # no quoting

    def test_like_single_quote_ptype(self):
        boundaries = self._run("' AND ", "' like '%")
        self.assertEqual(boundaries[0].ptype, 3)   # LIKE with single quote


if __name__ == "__main__":
    unittest.main()
