#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline tests for the JWT auditor: the dependency-free codec/crypto helpers in lib/utils/jwt.py
(parse/forge/crack/audit/detect) and the active scan engine in lib/techniques/jwt/inject.py
(acceptance oracle, forgery confirmation, kid/claim SQL-injection probe). The engine is driven against
a mock server by monkeypatching the transport, so the whole feature is validated deterministically on
Python 2.7 / 3.x with no network.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core.data import conf
from lib.core.enums import PLACE
from lib.utils.jwt import auditJWT
from lib.utils.jwt import crackHMAC
from lib.utils.jwt import encodeSegment
from lib.utils.jwt import findJWTs
from lib.utils.jwt import forgeJWT
from lib.utils.jwt import parseJWT
import lib.techniques.jwt.inject as inject


class JWTUtilsTest(unittest.TestCase):
    def test_parse_roundtrip(self):
        token = forgeJWT({"alg": "HS256", "typ": "JWT"}, {"user": "admin", "role": "user"}, key="secret")
        data = parseJWT(token)
        self.assertEqual(data["header"]["alg"], "HS256")
        self.assertEqual(data["payload"]["user"], "admin")

    def test_parse_rejects_non_jwt(self):
        for value in ("", "a.b", "a.b.c.d", "not.a.jwt", "eyJx.eyJx"):
            self.assertIsNone(parseJWT(value))

    def test_parse_rejects_non_string_alg(self):
        # RFC 7515: "alg" MUST be a string; a crafted token with e.g. an integer "alg" must not parse
        # (a permissive gate here would let a non-string "alg" reach auditJWT's alg.strip() and crash)
        token = "%s.%s." % (encodeSegment({"alg": 123}), encodeSegment({}))
        self.assertIsNone(parseJWT(token))

    def test_forge_none_is_unsigned(self):
        token = forgeJWT({"alg": "none"}, {"user": "admin"})
        self.assertTrue(token.endswith("."))
        self.assertEqual(parseJWT(token)["signature"], "")

    def test_crack_hmac_secret(self):
        token = forgeJWT({"alg": "HS256"}, {"user": "admin"}, key="s3cr3t")
        self.assertEqual(crackHMAC(token, ["a", "s3cr3t", "b"]), "s3cr3t")
        self.assertIsNone(crackHMAC(token, ["a", "b"]))
        self.assertIsNone(crackHMAC(token, ["s3cr3t"], limit=0))     # limit reached before the hit

    def test_crack_ignores_non_hmac(self):
        self.assertIsNone(crackHMAC("eyJhbGciOiJSUzI1NiJ9.eyJ1IjoxfQ.AAAA", ["secret"]))

    def test_audit_flags(self):
        ids = set(_[0] for _ in auditJWT(forgeJWT({"alg": "none"}, {"user": "admin"})))
        self.assertIn("alg-none", ids)
        self.assertIn("no-expiry", ids)

    def test_audit_weak_secret_and_headers(self):
        token = forgeJWT({"alg": "HS256", "kid": "1", "jku": "https://evil/x"}, {"user": "admin", "exp": 9999999999}, key="secret")
        ids = set(_[0] for _ in auditJWT(token, secrets=["secret"]))
        self.assertIn("weak-hmac-secret", ids)
        self.assertIn("header-key-injection", ids)
        self.assertIn("kid-injection", ids)

    def test_find_jwts_in_blob(self):
        token = forgeJWT({"alg": "HS256"}, {"user": "admin"}, key="secret")
        blob = "session=abc; auth=%s; theme=dark" % token
        self.assertEqual(findJWTs(blob), [token])
        self.assertEqual(findJWTs("no tokens here"), [])


class _MockServer(object):
    """A trivial JWT-consuming endpoint. `verify` decides how strict it is; `sink` optionally reflects
    a component (kid / a claim) into a fake SQL error, modelling an injectable key/claim lookup."""

    OK = "<html>welcome back, admin. secret area.</html>"
    DENY = "<html>access denied. please log in.</html>"
    NOROW = "<html>no matching record found.</html>"
    SQLERR = "<html>SQL syntax error near unclosed quotation mark</html>"

    def __init__(self, secret=None, acceptNone=False, verifySig=True, sink=None, alwaysError=False, dynamic=False):
        self.secret = secret
        self.acceptNone = acceptNone
        self.verifySig = verifySig
        self.sink = sink                # ("kid",)/("claim", name) string quote-sink, or ("numclaim", name) numeric sink
        self.alwaysError = alwaysError  # H2: page ALWAYS carries SQL-error text (must not be read as injection)
        self.dynamic = dynamic          # H3: response changes every hit (must not yield a boolean verdict)
        self._tick = 0

    def _wrap(self, page):
        if self.dynamic:
            self._tick += 1
            return "%s<!-- nonce %d -->" % (page, self._tick)
        return page

    def respond(self, token):
        if self.alwaysError:
            return self._wrap(self.SQLERR)

        data = parseJWT(token)
        if not data:
            return self._wrap(self.DENY)

        if self.sink is not None:
            reflected = data["header"].get("kid") if self.sink[0] == "kid" else (data["payload"].get(self.sink[1]) if isinstance(data["payload"], dict) else None)
            reflected = "" if reflected is None else str(reflected)
            if self.sink[0] in ("claim", "kid") and reflected.count("'") % 2 == 1:
                return self._wrap(self.SQLERR)                     # unbalanced quote -> string-context SQL error
            if self.sink[0] == "numclaim":
                if "'" in reflected:
                    return self._wrap(self.SQLERR)                 # quote in a numeric concat -> error
                m = re.match(r"^\d+ AND (\d+)=(\d+)$", reflected)
                if m:
                    return self._wrap(self.OK if m.group(1) == m.group(2) else self.NOROW)   # AND n=n true, n=n+1 false

        alg = (data["header"].get("alg") or "").lower()
        if alg == "none":
            return self._wrap(self.OK if self.acceptNone else self.DENY)
        if not self.verifySig:
            return self._wrap(self.OK)
        if self.secret and forgeJWT(data["header"], data["payload"], key=self.secret) == token:
            return self._wrap(self.OK)
        return self._wrap(self.DENY)


class JWTEngineTest(unittest.TestCase):
    def setUp(self):
        self._origGetPage = inject.Request.getPage
        self._origParams = conf.parameters
        self._origSecrets = inject._wordlistSecrets
        conf.skipUrlEncode = False
        conf.delay = 0
        conf.beep = False
        # keep the offline crack fast: the full 6 MB wordlist sweep is exercised by the utils tests; here
        # only the small common set is needed (a crackable token uses 'secret', which is in it)
        from lib.core.settings import JWT_COMMON_SECRETS
        inject._wordlistSecrets = lambda: iter(JWT_COMMON_SECRETS)

    def tearDown(self):
        inject.Request.getPage = self._origGetPage
        conf.parameters = self._origParams
        inject._wordlistSecrets = self._origSecrets
        inject._TOKEN = inject._PLACE = inject._HEADER = inject._HEADER_VALUE = None

    def _wire(self, token, server):
        conf.parameters = {PLACE.GET: "auth=%s" % token}

        def fakeGetPage(**kwargs):
            raw = kwargs.get("get") or kwargs.get("post") or kwargs.get("cookie") or ""
            if kwargs.get("auxHeaders"):
                raw = list(kwargs["auxHeaders"].values())[0]
            found = findJWTs(raw)
            return (server.respond(found[0] if found else raw), None, 200)

        inject.Request.getPage = staticmethod(fakeGetPage)

    def _run(self, token, server):
        self._wire(token, server)
        return dict((_[0], _) for _ in inject.jwtScan())

    def test_oracle_confirms_alg_none(self):
        # the server knows its real secret (so the original token is the authenticated baseline) but that
        # secret is not in sqlmap's crack list; its flaw is accepting an unsigned alg:none forgery
        token = forgeJWT({"alg": "HS256"}, {"user": "admin", "exp": 9999999999}, key="topsecret-not-in-list")
        findings = self._run(token, _MockServer(secret="topsecret-not-in-list", acceptNone=True))
        self.assertIn("alg-none-accepted", findings)
        self.assertEqual(findings["alg-none-accepted"][1], "critical")

    def test_oracle_confirms_signature_not_verified(self):
        token = forgeJWT({"alg": "HS256"}, {"user": "admin", "exp": 9999999999}, key="topsecret-not-in-list")
        findings = self._run(token, _MockServer(verifySig=False))
        self.assertIn("signature-not-verified", findings)

    def test_strict_server_yields_no_forgery(self):
        token = forgeJWT({"alg": "HS256"}, {"user": "admin", "exp": 9999999999}, key="topsecret-not-in-list")
        findings = self._run(token, _MockServer(secret="topsecret-not-in-list"))
        self.assertNotIn("alg-none-accepted", findings)
        self.assertNotIn("signature-not-verified", findings)

    def test_weak_secret_cracked_offline(self):
        token = forgeJWT({"alg": "HS256"}, {"user": "admin", "exp": 9999999999}, key="secret")
        findings = self._run(token, _MockServer(secret="secret"))
        self.assertIn("weak-hmac-secret", findings)

    def test_kid_sql_injection(self):
        token = forgeJWT({"alg": "none", "kid": "key1"}, {"user": "admin", "exp": 9999999999})
        findings = self._run(token, _MockServer(acceptNone=True, sink=("kid",)))
        self.assertIn("kid-injection-confirmed", findings)
        self.assertEqual(findings["kid-injection-confirmed"][1], "critical")

    def test_claim_sql_injection_via_alg_none(self):
        token = forgeJWT({"alg": "none"}, {"user": "admin", "exp": 9999999999})
        findings = self._run(token, _MockServer(acceptNone=True, sink=("claim", "user")))
        self.assertIn("claim-injection-confirmed", findings)

    def test_numeric_claim_sql_injection(self):
        # M4: a numeric claim (id) string-interpolated into SQL - detected in an unquoted 'AND n=n' context
        token = forgeJWT({"alg": "none"}, {"user": "admin", "id": 5, "exp": 9999999999})
        findings = self._run(token, _MockServer(acceptNone=True, sink=("numclaim", "id")))
        self.assertIn("claim-injection-confirmed", findings)

    def test_error_based_no_fp_when_baseline_has_sql_error(self):
        # H2: a page that ALWAYS contains SQL-error text must NOT be reported as an injection
        token = forgeJWT({"alg": "none", "kid": "k"}, {"user": "admin", "exp": 9999999999})
        findings = self._run(token, _MockServer(acceptNone=True, alwaysError=True))
        self.assertNotIn("kid-injection-confirmed", findings)
        self.assertNotIn("claim-injection-confirmed", findings)

    def test_boolean_no_fp_on_dynamic_page(self):
        # H3: a response that changes every hit must not yield a boolean SQL-injection verdict
        token = forgeJWT({"alg": "none", "kid": "k"}, {"user": "admin", "exp": 9999999999})
        findings = self._run(token, _MockServer(acceptNone=True, dynamic=True))
        self.assertNotIn("kid-injection-confirmed", findings)
        self.assertNotIn("claim-injection-confirmed", findings)

    def test_no_token_is_graceful(self):
        conf.parameters = {PLACE.GET: "q=hello"}
        inject.Request.getPage = staticmethod(lambda **kwargs: ("x", None, 200))
        self.assertEqual(inject.jwtScan(), None)


if __name__ == "__main__":
    unittest.main()
