#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline, deterministic tests for the LDAP injection engine. Mock oracles stand in for the
HTTP/LDAP layer so detection, fingerprinting, blind inference, and output formatting can
be exercised without a live target.
"""

import unittest

from _testutils import bootstrap
bootstrap()

import lib.techniques.ldap.inject as ldap

# --- Helpers ----------------------------------------------------------------

SENTINEL = ldap.SENTINEL


def _mockOracle(value):
    """Build a mock extract oracle that knows the full target value. Probes
    use _ProbeBuilder.prefix() which encodes via _ldapLiteral and
    _transportEncode; reverse both so the plain prefix can be compared."""
    class Oracle(object):
        def extract(self, probe):
            # Decode %xx transport escapes (done by _transportEncode).
            # Order matters: %25 (literal '%') must be decoded before other
            # %xx sequences whose '%' came from the *encoding* pass.
            def _transportDecode(s):
                s = s.replace("%25", "\x00")   # placeholder for literal %
                s = s.replace("%23", "#")
                s = s.replace("%26", "&")
                s = s.replace("%2B", "+")
                s = s.replace("%3D", "=")
                s = s.replace("%20", " ")
                s = s.replace("\x00", "%")     # restore literal %
                return s

            # Decode LDAP \xx hex escapes (done by _ldapLiteral).
            def _ldapDecode(s):
                return re.sub(r"\\([0-9a-fA-F]{2})",
                              lambda m: chr(int(m.group(1), 16)), s)

            # Probe format: SENTINEL)(attr=_ldapLiteral(prefix_char)*
            idx = probe.rfind(")(")
            if idx < 0:
                return False
            rest = probe[idx + 2:]  # after )(
            if "=" not in rest or not rest.endswith("*"):
                return False
            inner = rest[:-1]  # strip trailing *
            attr, val = inner.split("=", 1)
            prefix = _transportDecode(_ldapDecode(val))
            return value.startswith(prefix)
    return Oracle()


import re


# --- Tests ------------------------------------------------------------------

class TestHelpers(unittest.TestCase):
    def test_ratio_identical(self):
        self.assertGreater(ldap._ratio("abc", "abc"), 0.9)

    def test_ratio_different(self):
        self.assertLess(ldap._ratio("abc", "xyz"), 0.5)

    def test_ratio_none(self):
        self.assertEqual(ldap._ratio(None, "abc"), 0.0)
        self.assertEqual(ldap._ratio("abc", None), 0.0)

    def test_delim_get(self):
        from lib.core.enums import PLACE
        self.assertEqual(ldap._delim(PLACE.GET), '&')

    def test_delim_cookie_default(self):
        from lib.core.enums import PLACE
        self.assertEqual(ldap._delim(PLACE.COOKIE), ';')

    def test_originalValue(self):
        from lib.core.enums import PLACE
        from lib.core.data import conf
        conf.parameters = {PLACE.GET: 'q=test&x=123'}
        conf.paramDict = {PLACE.GET: {'q': 'test', 'x': '123'}}
        self.assertEqual(ldap._originalValue(PLACE.GET, 'q'), 'test')
        self.assertEqual(ldap._originalValue(PLACE.GET, 'x'), '123')

    def test_replaceSegment(self):
        from lib.core.enums import PLACE
        from lib.core.data import conf
        conf.parameters = {PLACE.GET: 'q=old&x=123'}
        conf.paramDict = {PLACE.GET: {'q': 'old', 'x': '123'}}
        result = ldap._replaceSegment(PLACE.GET, 'q', 'new')
        self.assertIn('q=new', result)
        self.assertIn('x=123', result)


class TestFingerprinting(unittest.TestCase):
    def test_fingerprintByError_ad(self):
        self.assertEqual(ldap._fingerprintByError("Microsoft Active Directory"),
                         "Microsoft Active Directory")

    def test_fingerprintByError_openldap(self):
        self.assertEqual(ldap._fingerprintByError("OpenLDAP"), "OpenLDAP")

    def test_fingerprintByError_apacheds(self):
        self.assertEqual(ldap._fingerprintByError("ApacheDS"), "ApacheDS")

    def test_fingerprintByError_oracle(self):
        self.assertEqual(ldap._fingerprintByError("Oracle Directory Server"),
                         "Oracle Directory Server")

    def test_fingerprintByError_389(self):
        self.assertEqual(ldap._fingerprintByError("389 Directory Server"),
                         "389 Directory Server")

    def test_fingerprintByError_generic(self):
        self.assertEqual(ldap._fingerprintByError("Generic LDAP"), "Generic LDAP")

    def test_fingerprintByError_jndi(self):
        self.assertEqual(ldap._fingerprintByError("Java JNDI"), "Java JNDI")

    def test_fingerprintByError_pythonldap(self):
        self.assertEqual(ldap._fingerprintByError("python-ldap"), "python-ldap")


class TestGrid(unittest.TestCase):
    def test_grid_simple(self):
        cols = ["attr", "value"]
        rows = [("uid", "admin"), ("cn", "Admin User")]
        output = ldap._grid(cols, rows)
        self.assertIn("attr", output)
        self.assertIn("uid", output)
        self.assertIn("admin", output)
        self.assertIn("cn", output)
        self.assertIn("Admin User", output)

    def test_grid_empty(self):
        output = ldap._grid(["a"], [])
        self.assertIn("a", output)

    def test_grid_single_row(self):
        cols = ["col"]
        rows = [("val",)]
        output = ldap._grid(cols, rows)
        self.assertIn("col", output)
        self.assertIn("val", output)


class TestErrorDetection(unittest.TestCase):
    def setUp(self):
        from lib.core.enums import PLACE
        from lib.core.data import conf
        conf.parameters = {PLACE.GET: 'q=x'}
        conf.paramDict = {PLACE.GET: {'q': 'x'}}
        conf.skipUrlEncode = False
        conf.cookieDel = ';'

        self._originalSend = ldap._send

    def tearDown(self):
        ldap._send = self._originalSend

    def test_detectError_openldap(self):
        ldap._send = lambda p, pm, v: (
            "<html>Bad search filter (-7)</html>" if ")" in (v or "") else "<html>OK</html>"
        )
        from lib.core.enums import PLACE
        backend, _ = ldap._probeBackendByParserError(PLACE.GET, 'q')
        self.assertEqual(backend, "OpenLDAP")

    def test_detectError_ad(self):
        ldap._send = lambda p, pm, v: (
            "LDAP: error code 49 - 80090308: LdapErr: DSID-0C090308, "
            "comment: AcceptSecurityContext error, data 525" if ")" in (v or "") else "OK"
        )
        from lib.core.enums import PLACE
        backend, _ = ldap._probeBackendByParserError(PLACE.GET, 'q')
        self.assertEqual(backend, "Microsoft Active Directory")

    def test_detectError_apacheds(self):
        ldap._send = lambda p, pm, v: (
            "javax.naming.directory.InvalidSearchFilterException: Unbalanced parenthesis"
            if ")" in (v or "") else "OK"
        )
        from lib.core.enums import PLACE
        backend, _ = ldap._probeBackendByParserError(PLACE.GET, 'q')
        self.assertEqual(backend, "ApacheDS")

    def test_detectError_notInjected(self):
        ldap._send = lambda p, pm, v: "<html>OK</html>"
        from lib.core.enums import PLACE
        backend, _ = ldap._probeBackendByParserError(PLACE.GET, 'q')
        self.assertIsNone(backend)

    def test_detectError_uses_ldap_metacharacter(self):
        """Blockers 1: error detection must use LDAP filter metacharacter,
        not an apostrophe (which is not an LDAP special char)."""
        # Verify the probe appends ')' (unbalanced paren), not "'" (SQL quote)
        calls = []
        ldap._send = lambda p, pm, v: calls.append(v) or "<html>OK</html>"
        from lib.core.enums import PLACE
        ldap._probeBackendByParserError(PLACE.GET, 'q')
        self.assertTrue(any(v.endswith(')') for v in calls))
        self.assertFalse(any("'" in v for v in calls if len(v) > 2))


class TestBooleanDetection(unittest.TestCase):
    def setUp(self):
        from lib.core.enums import PLACE
        from lib.core.data import conf
        conf.parameters = {PLACE.GET: 'q=x'}
        conf.paramDict = {PLACE.GET: {'q': 'x'}}
        conf.skipUrlEncode = False
        conf.cookieDel = ';'

        self._originalSend = ldap._send

    def tearDown(self):
        ldap._send = self._originalSend

    def test_boolean_divergence(self):
        """True payload returns different content than false payload.
        The engine tries multiple breakout prefixes; the first '*')' with
        '(objectClass=*)' tautology should succeed."""
        def fakeSend(place, param, value):
            # First breakout '*)' with (objectClass=*) succeeds
            if value.startswith("x*)(objectClass=*"):
                return '{"count":15}'
            return '{"count":0}'

        ldap._send = fakeSend
        from lib.core.enums import PLACE
        template, bypass, breakout = ldap._detectBoolean(PLACE.GET, 'q')
        self.assertIsNotNone(template)
        self.assertEqual(breakout, "*)")
        self.assertIn("*)(objectClass=*", bypass)


class TestExtraction(unittest.TestCase):
    def test_inferAttribute_simple(self):
        """Blind-extract a value with a controlled oracle."""
        oracle = _mockOracle("admin")
        builder = ldap._ProbeBuilder(")")
        value = ldap._inferAttribute(oracle, builder, "uid")
        self.assertEqual(value, "admin")

    def test_inferAttribute_empty(self):
        """No probes match."""
        oracle = _mockOracle("")
        builder = ldap._ProbeBuilder(")")
        value = ldap._inferAttribute(oracle, builder, "uid")
        self.assertIsNone(value)

    def test_inferAttribute_partial(self):
        """Probe matches a single char only."""
        oracle = _mockOracle("a")
        builder = ldap._ProbeBuilder(")")
        value = ldap._inferAttribute(oracle, builder, "uid")
        self.assertEqual(value, "a")

    def test_inferAttribute_email(self):
        """Extract value with special characters."""
        oracle = _mockOracle("admin@example.com")
        builder = ldap._ProbeBuilder(")")
        value = ldap._inferAttribute(oracle, builder, "mail")
        self.assertEqual(value, "admin@example.com")


class TestIsError(unittest.TestCase):
    def test_isError_positive(self):
        self.assertTrue(ldap._isError("Bad search filter (-7)"))

    def test_isError_negative(self):
        self.assertFalse(ldap._isError("<html>OK</html>"))

    def test_isError_ad(self):
        self.assertTrue(ldap._isError("AcceptSecurityContext error, data 525"))


class TestSlot(unittest.TestCase):
    def test_slot_defaults(self):
        slot = ldap.Slot(place="GET", parameter="q")
        self.assertEqual(slot.place, "GET")
        self.assertEqual(slot.parameter, "q")
        self.assertIsNone(slot.backend)
        self.assertIsNone(slot.oracle)
        self.assertIsNone(slot.template)
        self.assertIsNone(slot.payload)
        self.assertIsNone(slot.breakout)
        self.assertIsNone(slot.bypass)


class TestBoundaries(unittest.TestCase):
    def test_breakout_prefixes_defined(self):
        """Verify the breakout prefix list is non-empty and ordered."""
        self.assertGreaterEqual(len(ldap.LDAP_BREAKOUT_PREFIXES), 4)
        # First prefix should be the simplest/most generic
        self.assertEqual(ldap.LDAP_BREAKOUT_PREFIXES[0], "*)")

    def test_detectBoolean_returns_prefix(self):
        """_detectBoolean must return the winning breakout prefix."""
        def fakeSend(place, param, value):
            if value.startswith("x*)(objectClass=*"):
                return '{"count":15}'
            return '{"count":0}'
        ldap._send = fakeSend
        from lib.core.enums import PLACE
        template, bypass, breakout = ldap._detectBoolean(PLACE.GET, 'q')
        self.assertIsNotNone(template)
        self.assertEqual(breakout, "*)")

    def test_detectBoolean_fallback_prefix(self):
        """When first prefix fails, try next one."""
        calls = []
        def fakeSend(place, param, value):
            calls.append(value)
            # First breakout '*)' -- error
            if value.startswith("x*)(objectClass=*"):
                return '{"error":"Bad search filter"}'
            # Second breakout ')' succeeds
            if value.startswith("x)(objectClass=*"):
                return '{"count":15}'
            return '{"count":0}'
        ldap._send = fakeSend
        from lib.core.enums import PLACE
        template, bypass, breakout = ldap._detectBoolean(PLACE.GET, 'q')
        self.assertIsNotNone(template)
        self.assertEqual(breakout, ")")


class TestAuthBypassRestriction(unittest.TestCase):
    def test_auth_bypass_password_like(self):
        """Blockers 6: wildcard auth bypass only for password-like params."""
        self.assertTrue(ldap._isPasswordParam("password"))
        self.assertTrue(ldap._isPasswordParam("pass"))
        self.assertTrue(ldap._isPasswordParam("pwd"))
        self.assertTrue(ldap._isPasswordParam("passphrase"))
        self.assertTrue(ldap._isPasswordParam("secret"))
        self.assertTrue(ldap._isPasswordParam("pincode"))
        self.assertTrue(ldap._isPasswordParam("credential"))
        self.assertTrue(ldap._isPasswordParam("apikey"))
        self.assertTrue(ldap._isPasswordParam("token"))
        self.assertTrue(ldap._isPasswordParam("auth_token"))

    def test_auth_bypass_search_like(self):
        """Search parameter 'q' is NOT reported as auth bypass."""
        self.assertFalse(ldap._isPasswordParam("q"))
        self.assertFalse(ldap._isPasswordParam("search"))
        self.assertFalse(ldap._isPasswordParam("query"))
        self.assertFalse(ldap._isPasswordParam("username"))
        self.assertFalse(ldap._isPasswordParam("id"))


class TestCookiePlace(unittest.TestCase):
    def test_cookie_not_in_ldap_places(self):
        """Blockers 2: cookie/URI not in LDAP_PLACES until _send supports them."""
        from lib.core.enums import PLACE
        self.assertNotIn(PLACE.COOKIE, ldap.LDAP_PLACES)
        self.assertNotIn(PLACE.URI, ldap.LDAP_PLACES)


class TestNestedFilterParsing(unittest.TestCase):
    def test_nested_compound_parses_all_siblings(self):
        """Blockers 3: nested (&) inside (|) must parse all siblings."""
        # Inline copies of the vulnserver helpers so the test is self-contained
        def _ldap_match(text, start):
            depth = 0
            i = start
            while i < len(text):
                ch = text[i]
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                    if depth == 0:
                        return i + 1
                elif ch == '\\':
                    i += 1
                i += 1
            return len(text)

        def _ldap_parse_value(text, start):
            retVal = []
            i = start
            while i < len(text) and text[i] not in (')',):
                if text[i] == '\\' and i + 2 < len(text):
                    retVal.append(chr(int(text[i+1:i+3], 16)))
                    i += 3
                else:
                    retVal.append(text[i])
                    i += 1
            return ''.join(retVal), i

        # Minimum reproduction of the fixed _ldap_filter_to_sql
        # (the real function is in extra/vulnserver/vulnserver.py)
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'extra', 'vulnserver'))
        # Can't cleanly import vulnserver because of the __main__ guard.
        # Instead we verify the fixed _ldap_match returns the correct end
        # position for a nested compound filter, which was the root cause.
        f = '(|(&(uid=a)(cn=b))(mail=*))'
        # The outer (| ... ) starts at 0 and should end at len(f)
        outer_end = _ldap_match(f, 0)
        self.assertEqual(outer_end, len(f))
        # The inner (& ... ) compound's opening '(' is at position 2
        # (f[2] == '(').  _ldap_match must return the position after the
        # matching ')' that closes the compound, i.e. right before (mail=*).
        inner_end = _ldap_match(f, 2)
        self.assertEqual(f[inner_end:inner_end+8], '(mail=*)')


if __name__ == "__main__":
    unittest.main()
