#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Additional unit coverage for lib/core/common.py, lib/core/option.py and
lib/core/target.py, targeting *pure* (or near-pure) functions and branches NOT
already exercised by the existing test modules:

  * tests/test_common_utils.py / test_common_parsers.py / test_core_more.py
  * tests/test_option_setup.py / test_option_more.py
  * tests/test_target_parsing.py

This file instead covers (common.py):

  boldifyMessage, calculateDeltaSeconds, commonFinderOnly,
  enumValueToNameLookup, extractErrorMessage, filePathToSafeString,
  isWindowsDriveLetterPath, cleanReplaceUnicode, trimAlphaNum,
  removePostHintPrefix, safeExpandUser, safeFilepathEncode,
  serializeObject/unserializeObject, applyFunctionRecursively,
  extractExpectedValue, getHeader, getRequestHeader, parseJson,
  parsePasswordHash, findMultipartPostBoundary, setTechnique/getTechnique,
  extractRegexResult, extractTextTagContent, getFilteredPageContent,
  checkFile, listToStrValue, intersect, isZipFile, checkOldOptions.

(option.py):

  _setHTTPAuthentication (basic/ntlm/bearer/pki + error branches),
  _setWriteFile, _setHTTPTimeout, _setAuthCred.

Everything runs in isolation: no network, no DBMS, no persistent filesystem
mutation. All mutated conf/kb/Backend/socket state is snapshotted and restored.
"""

import os
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.core.option as option
from lib.core.data import conf, kb, paths
from lib.core.enums import (
    AUTH_TYPE,
    DBMS,
    EXPECTED,
    HTTP_HEADER,
    SORT_ORDER,
)
from lib.core.exception import (
    SqlmapFilePathException,
    SqlmapMissingMandatoryOptionException,
    SqlmapMissingDependence,
    SqlmapSyntaxException,
    SqlmapSystemException,
)
from lib.core.settings import NULL
from lib.core.common import (
    applyFunctionRecursively,
    boldifyMessage,
    calculateDeltaSeconds,
    checkFile,
    checkOldOptions,
    cleanReplaceUnicode,
    commonFinderOnly,
    enumValueToNameLookup,
    extractErrorMessage,
    extractExpectedValue,
    extractRegexResult,
    extractTextTagContent,
    filePathToSafeString,
    findMultipartPostBoundary,
    getFilteredPageContent,
    getHeader,
    getRequestHeader,
    getText,
    getTechnique,
    intersect,
    isWindowsDriveLetterPath,
    isZipFile,
    listToStrValue,
    parseJson,
    parsePasswordHash,
    removePostHintPrefix,
    safeExpandUser,
    safeFilepathEncode,
    serializeObject,
    setTechnique,
    trimAlphaNum,
    unserializeObject,
)
from thirdparty.six.moves import urllib as _urllib


class _FakeRequest(object):
    """Minimal stand-in for urllib2.Request used by getRequestHeader()."""

    def __init__(self, headers):
        self.headers = headers

    def header_items(self):
        return self.headers.items()


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


class TestOptionSetWriteFile(unittest.TestCase):

    def setUp(self):
        self._saved = (conf.fileWrite, conf.fileDest, conf.get("fileWriteType"))

    def tearDown(self):
        conf.fileWrite, conf.fileDest, conf.fileWriteType = self._saved

    def test_noop_when_no_filewrite(self):
        conf.fileWrite = None
        self.assertIsNone(option._setWriteFile())

    def test_raises_on_missing_local_file(self):
        conf.fileWrite = "/no/such/local_file_xyz"
        conf.fileDest = "/var/www/x"
        with self.assertRaises(SqlmapFilePathException):
            option._setWriteFile()

    def test_raises_on_missing_dest(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            conf.fileWrite = path
            conf.fileDest = None
            with self.assertRaises(SqlmapMissingMandatoryOptionException):
                option._setWriteFile()
        finally:
            os.unlink(path)

    def test_sets_file_write_type(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            conf.fileWrite = path
            conf.fileDest = "/var/www/x"
            option._setWriteFile()
            self.assertIn(conf.fileWriteType, ("text", "binary"))
        finally:
            os.unlink(path)


class TestOptionSetHTTPTimeout(unittest.TestCase):

    def setUp(self):
        self._savedTimeout = conf.timeout
        self._savedSocket = socket.getdefaulttimeout()

    def tearDown(self):
        conf.timeout = self._savedTimeout
        socket.setdefaulttimeout(self._savedSocket)

    def test_explicit_timeout(self):
        conf.timeout = 10
        option._setHTTPTimeout()
        self.assertEqual(conf.timeout, 10.0)

    def test_below_minimum_is_clamped(self):
        conf.timeout = 1
        option._setHTTPTimeout()
        self.assertEqual(conf.timeout, 3.0)

    def test_default_when_unset(self):
        conf.timeout = None
        option._setHTTPTimeout()
        self.assertEqual(conf.timeout, 30.0)


class TestOptionSetHTTPAuthentication(unittest.TestCase):

    def setUp(self):
        self._saved = {
            "authType": conf.authType,
            "authCred": conf.authCred,
            "authFile": conf.authFile,
            "authUsername": conf.authUsername,
            "authPassword": conf.authPassword,
            "httpHeaders": list(conf.httpHeaders),
            "passwordMgr": kb.passwordMgr,
        }
        # provide a real password manager so the basic/digest branches work
        kb.passwordMgr = _urllib.request.HTTPPasswordMgrWithDefaultRealm()

    def tearDown(self):
        conf.authType = self._saved["authType"]
        conf.authCred = self._saved["authCred"]
        conf.authFile = self._saved["authFile"]
        conf.authUsername = self._saved["authUsername"]
        conf.authPassword = self._saved["authPassword"]
        conf.httpHeaders = self._saved["httpHeaders"]
        kb.passwordMgr = self._saved["passwordMgr"]

    def test_noop_when_nothing_set(self):
        conf.authType = None
        conf.authCred = None
        conf.authFile = None
        self.assertIsNone(option._setHTTPAuthentication())

    def test_basic_credentials_parsed(self):
        conf.authType = "basic"
        conf.authCred = "admin:secret"
        conf.authFile = None
        option._setHTTPAuthentication()
        self.assertEqual(conf.authUsername, "admin")
        self.assertEqual(conf.authPassword, "secret")

    def test_ntlm_credentials_parsed(self):
        conf.authType = "ntlm"
        conf.authCred = "DOMAIN\\user:pa:ss"
        conf.authFile = None
        conf.authUsername = None
        conf.authPassword = None
        # The python-ntlm handler module is optional; credential parsing happens
        # before the handler import, so the parsed creds are set regardless.
        try:
            option._setHTTPAuthentication()
        except SqlmapMissingDependence:
            pass
        self.assertEqual(conf.authUsername, "DOMAIN\\user")
        self.assertEqual(conf.authPassword, "pa:ss")

    def test_ntlm_bad_format_raises(self):
        conf.authType = "ntlm"
        conf.authCred = "nobackslash:pass"
        conf.authFile = None
        with self.assertRaises(SqlmapSyntaxException):
            option._setHTTPAuthentication()

    def test_bearer_appends_authorization_header(self):
        conf.authType = "bearer"
        conf.authCred = "tok123"
        conf.authFile = None
        conf.httpHeaders = []
        option._setHTTPAuthentication()
        self.assertIn((HTTP_HEADER.AUTHORIZATION, "Bearer tok123"), conf.httpHeaders)

    def test_unsupported_type_raises(self):
        conf.authType = "wrongtype"
        conf.authCred = "a:b"
        conf.authFile = None
        with self.assertRaises(SqlmapSyntaxException):
            option._setHTTPAuthentication()

    def test_type_without_credentials_raises(self):
        conf.authType = "basic"
        conf.authCred = None
        conf.authFile = None
        with self.assertRaises(SqlmapSyntaxException):
            option._setHTTPAuthentication()

    def test_credentials_without_type_raises(self):
        conf.authType = None
        conf.authCred = "a:b"
        conf.authFile = None
        with self.assertRaises(SqlmapSyntaxException):
            option._setHTTPAuthentication()

    def test_authfile_without_type_defaults_to_pki(self):
        conf.authType = None
        conf.authCred = None
        conf.authFile = __file__  # exists, so checkFile() inside PKI branch passes
        option._setHTTPAuthentication()
        self.assertEqual(conf.authType, AUTH_TYPE.PKI)

    def test_pki_type_without_authfile_raises(self):
        conf.authType = "pki"
        conf.authCred = "x"
        conf.authFile = None
        with self.assertRaises(SqlmapSyntaxException):
            option._setHTTPAuthentication()


class TestOptionSetAuthCred(unittest.TestCase):

    def setUp(self):
        self._saved = {
            "scheme": conf.scheme,
            "hostname": conf.hostname,
            "port": conf.port,
            "authUsername": conf.authUsername,
            "authPassword": conf.authPassword,
            "passwordMgr": kb.passwordMgr,
        }

    def tearDown(self):
        conf.scheme = self._saved["scheme"]
        conf.hostname = self._saved["hostname"]
        conf.port = self._saved["port"]
        conf.authUsername = self._saved["authUsername"]
        conf.authPassword = self._saved["authPassword"]
        kb.passwordMgr = self._saved["passwordMgr"]

    def test_noop_without_password_manager(self):
        kb.passwordMgr = None
        # Must not raise when there is no password manager configured
        self.assertIsNone(option._setAuthCred())

    def test_adds_credentials_to_manager(self):
        kb.passwordMgr = _urllib.request.HTTPPasswordMgrWithDefaultRealm()
        conf.scheme = "http"
        conf.hostname = "host"
        conf.port = 80
        conf.authUsername = "u"
        conf.authPassword = "p"
        option._setAuthCred()
        self.assertEqual(
            kb.passwordMgr.find_user_password(None, "http://host:80"),
            ("u", "p"),
        )


if __name__ == "__main__":
    unittest.main()
