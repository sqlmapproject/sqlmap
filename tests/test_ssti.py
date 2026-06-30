#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Offline tests for the SSTI detection and fingerprinting engine. Mock _send() stands
in for the HTTP/Jinja2 layer so engine table integrity, arithmetic proof, error
detection, boolean oracle, distinguishing probes, and fingerprinting can be
exercised without a live target.
"""

import unittest

from _testutils import bootstrap
bootstrap()

import lib.techniques.ssti.inject as ssti


SENTINEL = ssti.SENTINEL


class TestHelpers(unittest.TestCase):
    def test_ratio(self):
        self.assertGreater(ssti._ratio("abc", "abc"), 0.9)
        self.assertLess(ssti._ratio("abc", "xyz"), 0.5)

    def test_delim(self):
        from lib.core.enums import PLACE
        self.assertEqual(ssti._delim(PLACE.GET), '&')
        self.assertEqual(ssti._delim(PLACE.COOKIE), ';')


class TestEngineTable(unittest.TestCase):
    def test_all_engines_have_required_fields(self):
        for engine in ssti._ENGINE_TABLE:
            self.assertTrue(len(engine.name) > 0)
            self.assertTrue(len(engine.delimiter) > 0)

    def test_arithmetic_engines_have_format_strings(self):
        noArith = ("Velocity", "Handlebars")
        for engine in ssti._ENGINE_TABLE:
            if engine.name not in noArith:
                self.assertIn("%d", engine.arithmeticFmt,
                    "Engine '%s' arithmeticFmt must contain %%d placeholders" % engine.name)

    def test_error_probes_present(self):
        for engine in ssti._ENGINE_TABLE:
            if engine.errorRegex:
                self.assertTrue(len(engine.errorProbes) > 0,
                    "Engine '%s' has errorRegex but no errorProbes" % engine.name)

    def test_distinguishing_probes_for_curly_engines(self):
        curlyEngines = [e for e in ssti._ENGINE_TABLE if e.delimiter == "{{"]
        withProbes = [e for e in curlyEngines if e.distinguishingProbe]
        # Jinja2 and Twig are distinguished by trueRendered/falseRendered;
        # Twig/Handlebars have distinguishing probes. At least one curly engine
        # must have a probe, but Jinja2 can rely on boolean rendering difference.
        self.assertGreaterEqual(len(withProbes), 1,
            "At least one {{}}-delimited engine needs a distinguishing probe")

    def test_boolean_payloads_differ(self):
        for engine in ssti._ENGINE_TABLE:
            self.assertNotEqual(engine.booleanTrue, engine.booleanFalse,
                "Engine '%s' true/false payloads must differ" % engine.name)
            if engine.trueRendered:
                self.assertNotEqual(engine.trueRendered, engine.falseRendered,
                    "Engine '%s' true/false rendered values must differ" % engine.name)


class TestArithmeticDetection(unittest.TestCase):
    def setUp(self):
        self.original_send = ssti._send

    def tearDown(self):
        ssti._send = self.original_send

    def test_jinja2_arithmetic_control_pair(self):
        engine = ssti._ENGINE_TABLE[0]  # Jinja2

        def mock(place, parameter, value):
            import re
            m = re.search(r"\{\{ (\d+)\*(\d+)", value)
            if m:
                a, b = int(m.group(1)), int(m.group(2))
                return "Hello %d" % (a * b)
            return "Hello " + value

        ssti._send = mock
        self.assertTrue(ssti._probeArithmetic("GET", "q", engine))

    def test_arithmetic_requires_both_results_correct(self):
        engine = ssti._ENGINE_TABLE[0]

        def mock(place, parameter, value):
            return "Hello 42"  # always returns 42 regardless of payload

        ssti._send = mock
        # Control pair check: result1 must NOT appear in page2 and vice versa
        self.assertFalse(ssti._probeArithmetic("GET", "q", engine))

    def test_handlebars_skipped(self):
        engine = [e for e in ssti._ENGINE_TABLE if e.name == "Handlebars"][0]
        self.assertFalse(ssti._probeArithmetic("GET", "q", engine))


class TestErrorDetection(unittest.TestCase):
    def setUp(self):
        self.original_send = ssti._send

    def tearDown(self):
        ssti._send = self.original_send

    def test_jinja2_error_detected(self):
        engine = ssti._ENGINE_TABLE[0]

        def mock(place, parameter, value):
            if "{{" in value and "unknown" in value:
                return "jinja2.exceptions.TemplateSyntaxError: unexpected '}'"
            return "Hello " + value

        ssti._send = mock
        page = ssti._probeError("GET", "q", engine)
        self.assertIsNotNone(page)

    def test_no_error_on_normal_response(self):
        engine = ssti._ENGINE_TABLE[0]

        def mock(place, parameter, value):
            return "Hello " + value

        ssti._send = mock
        page = ssti._probeError("GET", "q", engine)
        self.assertIsNone(page)

    def test_backend_from_error(self):
        page = "jinja2.exceptions.UndefinedError: 'foo' is undefined"
        backend = ssti._backendFromError(page)
        self.assertIsNotNone(backend)


class TestDistinguishingProbes(unittest.TestCase):
    def setUp(self):
        self.original_send = ssti._send

    def tearDown(self):
        ssti._send = self.original_send

    def test_jinja2_no_distinguishing_probe(self):
        engine = ssti._ENGINE_TABLE[0]  # Jinja2
        self.assertFalse(engine.distinguishingProbe,
            "Jinja2 uses trueRendered/falseRendered for disambiguation, not a separate probe")

    def test_no_distinguishing_without_probe(self):
        engine = [e for e in ssti._ENGINE_TABLE if e.name == "Pug/Jade"][0]
        self.assertFalse(ssti._probeDistinguishing("GET", "q", engine))

    def test_comment_probe_reflection_rejected(self):
        """Comment-style probe reflected verbatim must not pass."""
        engine = [e for e in ssti._ENGINE_TABLE if e.name == "Freemarker"][0]

        def mock(place, parameter, value):
            if "<#--" in value:
                return "Hello <#-- freemarker -->"  # raw reflection
            return "Hello " + value

        ssti._send = mock
        self.assertFalse(ssti._probeDistinguishing("GET", "q", engine))


class TestBooleanDetection(unittest.TestCase):
    def setUp(self):
        self.original_send = ssti._send

    def tearDown(self):
        ssti._send = self.original_send

    def test_jinja2_boolean(self):
        engine = ssti._ENGINE_TABLE[0]

        def mock(place, parameter, value):
            if "True" in value:
                return "Hello True"
            elif "False" in value:
                return "Hello False"
            return "Hello " + value

        ssti._send = mock
        template = ssti._detectBoolean("GET", "q", engine)
        self.assertIsNotNone(template)

    def test_no_boolean_when_true_false_same(self):
        engine = ssti._ENGINE_TABLE[0]

        def mock(place, parameter, value):
            return "same response"

        ssti._send = mock
        template = ssti._detectBoolean("GET", "q", engine)
        self.assertIsNone(template)

    def test_plain_reflection_rejected(self):
        """Raw payload reflection must not pass boolean detection."""
        engine = ssti._ENGINE_TABLE[0]

        def mock(place, parameter, value):
            return "Hello " + value  # reflects payload verbatim

        ssti._send = mock
        template = ssti._detectBoolean("GET", "q", engine)
        self.assertIsNone(template)


class TestFingerprint(unittest.TestCase):
    def setUp(self):
        self.original_send = ssti._send

    def tearDown(self):
        ssti._send = self.original_send

    def test_jinja2_fingerprinted_with_arith_and_boolean(self):
        import re

        def mock(place, parameter, value):
            m = re.search(r"\{\{ (\d+)\*(\d+)", value)
            if m:
                return "Hello %d" % (int(m.group(1)) * int(m.group(2)))
            if "True" in value:
                return "Hello True"   # Jinja2-style boolean rendering
            if "False" in value:
                return "Hello False"
            if "unknown|filter" in value:
                return "jinja2.exceptions.TemplateSyntaxError: unexpected '}'"
            return "Hello " + value

        ssti._send = mock
        engine, evidence = ssti._fingerprint("GET", "q")
        self.assertIsNotNone(engine)
        self.assertIn("Jinja2", engine.name)
        self.assertTrue(evidence.get("arithmetic"))
        self.assertTrue(evidence.get("boolean"))


class TestCrossEngineDisambiguation(unittest.TestCase):
    def setUp(self):
        self.original_send = ssti._send

    def tearDown(self):
        ssti._send = self.original_send

    def test_jinja2_preferred_over_twig_via_boolean_rendering(self):
        """Jinja2 and Twig share {{ }} but differ in boolean rendering.
        Jinja2 renders True as 'True', Twig renders true as '1'.
        Our detection uses trueRendered for intrinsic discrimination."""
        import re

        def mock(place, parameter, value):
            m = re.search(r"\{\{ (\d+)\*(\d+)", value)
            if m:
                return "Hello %d" % (int(m.group(1)) * int(m.group(2)))
            # Twig-style boolean rendering (true -> 1, false -> empty)
            if "{{ true }}" in value:
                return "Hello 1"
            if "{{ false }}" in value:
                return "Hello "
            if "{{ True }}" in value:
                return "Hello 1"  # Jinja2 True payload would not match this
            return "Hello " + value

        ssti._send = mock
        engine, evidence = ssti._fingerprint("GET", "q")
        self.assertIsNotNone(engine)
        # Twig should win because its boolean payloads match the mock
        self.assertIn("Twig", engine.name)


class TestBooleanUniqueness(unittest.TestCase):
    def test_jinja2_boolean_unique_among_curlies(self):
        jinja2 = ssti._ENGINE_TABLE[0]
        self.assertTrue(ssti._booleanUniquelyIdentifies(jinja2))

    def test_freemarker_boolean_unique_with_computer_format(self):
        freemarker = [e for e in ssti._ENGINE_TABLE if e.name == "Freemarker"][0]
        # FreeMarker uses ${true?c} (computer-format), distinct from SpringEL's ${true} and
        # Mako's ${True}, so its boolean rendering now uniquely identifies it within the ${ } family
        self.assertTrue(ssti._booleanUniquelyIdentifies(freemarker))
        spring = [e for e in ssti._ENGINE_TABLE if "Spring" in e.name][0]
        self.assertTrue(ssti._booleanUniquelyIdentifies(spring))

    def test_jinja2_with_arithmetic_and_boolean_is_exact(self):
        """Arithmetic + boolean (unique) should produce exact engine name,
        not a family/probable guess."""
        import re

        def mock(place, parameter, value):
            m = re.search(r"\{\{ (\d+)\*(\d+)", value)
            if m:
                return "Hello %d" % (int(m.group(1)) * int(m.group(2)))
            if "True" in value:
                return "Hello True"
            if "False" in value:
                return "Hello False"
            return "Hello " + value

        ssti._send = mock
        engine, evidence = ssti._fingerprint("GET", "q")
        self.assertIsNotNone(engine)
        # Boolean is unique -> should NOT be marked "(probable"
        self.assertNotIn("(probable", engine.name)
        self.assertIn("Jinja2", engine.name)


class TestTakeoverGate(unittest.TestCase):
    def test_can_takeover_exact_engine_with_proof(self):
        engine = ssti._ENGINE_TABLE[0]  # Jinja2
        evidence = {"arithmetic": True, "boolean": True}
        self.assertTrue(ssti._canTakeover(engine, evidence))

    def test_cannot_takeover_probable_engine(self):
        engine = ssti._ENGINE_TABLE[0]._replace(name="Jinja2/Twig/Handlebars-like (probable Jinja2)")
        evidence = {"arithmetic": True}
        self.assertFalse(ssti._canTakeover(engine, evidence))

    def test_cannot_takeover_without_proof(self):
        engine = ssti._ENGINE_TABLE[0]
        evidence = {}
        self.assertFalse(ssti._canTakeover(engine, evidence))

    def test_cannot_takeover_without_payloads(self):
        engine = [e for e in ssti._ENGINE_TABLE if e.name == "Handlebars"][0]
        evidence = {"arithmetic": True}
        self.assertFalse(ssti._canTakeover(engine, evidence))


class TestRequestMutation(unittest.TestCase):
    """Verify _replaceSegment() correctly mutates parameter strings."""

    def setUp(self):
        self.original_send = ssti._send
        self._orig_params = dict(ssti.conf.parameters) if hasattr(ssti.conf, 'parameters') else {}
        self._orig_paramDict = dict(ssti.conf.paramDict) if hasattr(ssti.conf, 'paramDict') else {}
        self._orig_cookieDel = getattr(ssti.conf, 'cookieDel', None)

    def tearDown(self):
        ssti._send = self.original_send
        if hasattr(ssti.conf, 'parameters'):
            ssti.conf.parameters.clear()
            ssti.conf.parameters.update(self._orig_params)
        if hasattr(ssti.conf, 'paramDict'):
            ssti.conf.paramDict.clear()
            ssti.conf.paramDict.update(self._orig_paramDict)
        if self._orig_cookieDel is not None:
            ssti.conf.cookieDel = self._orig_cookieDel

    def test_replace_segment_single_param(self):
        ssti.conf.parameters = {"GET": "q=x"}
        result = ssti._replaceSegment("GET", "q", "test")
        self.assertEqual(result, "q=test")

    def test_replace_segment_multi_param(self):
        ssti.conf.parameters = {"GET": "q=x&a=1&b=2"}
        result = ssti._replaceSegment("GET", "a", "99")
        self.assertEqual(result, "q=x&a=99&b=2")

    def test_replace_segment_post(self):
        ssti.conf.parameters = {"POST": "user=admin&pass=secret"}
        result = ssti._replaceSegment("POST", "pass", "newpass")
        self.assertEqual(result, "user=admin&pass=newpass")

    def test_replace_segment_cookie_delim(self):
        from lib.core.enums import PLACE
        ssti.conf.parameters = {PLACE.COOKIE: "a=1;b=2"}
        ssti.conf.cookieDel = ";"
        result = ssti._replaceSegment(PLACE.COOKIE, "b", "xx")
        self.assertEqual(result, "a=1;b=xx")

    def test_replace_segment_missing_param(self):
        ssti.conf.parameters = {"GET": "a=1"}
        ssti.conf.paramDict = {"GET": {"a": "1", "b": "2"}}
        result = ssti._replaceSegment("GET", "b", "xx")
        self.assertEqual(result, "a=1&b=xx")


class TestExecuteCommand(unittest.TestCase):
    def setUp(self):
        self.original_send = ssti._send
        self.original_dumper = getattr(ssti.conf, 'dumper', None)
        # Provide a mock dumper so _executeCommand doesn't crash on conf.dumper
        from lib.core.datatype import AttribDict
        ssti.conf.dumper = AttribDict()
        ssti.conf.dumper.singleString = lambda msg: None

    def tearDown(self):
        ssti._send = self.original_send
        if self.original_dumper is not None:
            ssti.conf.dumper = self.original_dumper

    def test_error_page_skipped(self):
        """RCE payload that triggers a template error is skipped; next payload tried."""
        engine = ssti._ENGINE_TABLE[0]  # Jinja2
        calls = []

        def mock(place, parameter, value):
            calls.append(value)
            if "cycler" in value:
                return "jinja2.exceptions.UndefinedError: 'cycler' is undefined"
            if "config" in value:
                return "Hello output-from-config"
            return "Hello " + value

        ssti._send = mock
        ssti._executeCommand("GET", "q", engine, "test")
        # Should skip cycler (error) and use config (valid output)
        self.assertTrue(any("config" in c for c in calls),
            "Should have tried the second payload after error skip")

    def test_all_error_pages_produce_warning(self):
        """When all RCE payloads produce template errors, no success is reported.
        _executeCommand sends baseline + one request per fallback payload."""
        engine = ssti._ENGINE_TABLE[0]
        calls = []

        def mock(place, parameter, value):
            calls.append(value)
            return "jinja2.exceptions.TemplateSyntaxError: unexpected token"

        ssti._send = mock
        ssti._executeCommand("GET", "q", engine, "test")
        # 1 baseline + N payload attempts = N+1 calls
        self.assertEqual(len(calls), len(engine.rcePayloads) + 1,
            "Should have tried all payloads (baseline + one per fallback) before giving up")


class TestCommandEscaping(unittest.TestCase):
    def test_escape_single_quoted(self):
        self.assertEqual(ssti._escapeSingleQuoted("hello"), "hello")
        self.assertEqual(ssti._escapeSingleQuoted("it's"), "it\\'s")
        self.assertEqual(ssti._escapeSingleQuoted("a\\b"), "a\\\\b")


class TestEngineMatrix(unittest.TestCase):
    """For EVERY engine in the table, stand up a faithful mock server running that
    engine and assert _fingerprint() identifies it. This proves each engine's full
    detection path (arithmetic/boolean/error/distinguishing) actually works end to
    end - not just Jinja2 - and guards against regressions like the ERB '%>' format
    bug where a delimiter containing '%' silently disabled arithmetic detection."""

    def setUp(self):
        self.original_send = ssti._send

    def tearDown(self):
        ssti._send = self.original_send

    # Digit-free, boolean-word-free sample errors that match each engine's errorRegex.
    # (digit/boolean-free so a sibling engine's boolean probe falling through to the error
    # branch on this server is still correctly rejected.)
    _ERRORS = {
        "Jinja2": "jinja2.exceptions.TemplateSyntaxError: unexpected end of template",
        "Mako": "mako.exceptions.SyntaxException: unclosed control structure",
        "Twig": "Twig_Error_Syntax: unexpected token in template",
        "Freemarker": "freemarker.core.ParseException: encountered unexpected directive",
        "Velocity": "org.apache.velocity.runtime.parser.ParseErrorException: encountered eof",
        "Spring EL / Thymeleaf": "org.springframework.expression.spel.SpelParseException: bad node",
        "ERB": "(erb): syntax error, unexpected end-of-input",
        "Pug/Jade": "pug: unexpected token in template",
        "Handlebars": "Handlebars: Parse error on line one",
    }

    # Real divide-by-zero error text per language family (captured from live Mako/ERB/Jinja2
    # backends), so the S2 family probe can be exercised. JS yields Infinity (no error).
    _DIVZERO = {
        "python": "ZeroDivisionError: division by zero",
        "ruby":   "ZeroDivisionError: divided by 0",
        "php":    "DivisionByZeroError: Division by zero",
        "java":   "java.lang.ArithmeticException: / by zero",
        "nodejs": "Hello Infinity",
    }

    @staticmethod
    def _make_server(engine, errors):
        import re
        op = re.escape(engine.delimiter)
        cl = re.escape(engine.delimiterClose)
        arithRe = re.compile(op + r"\s*(\d+)\s*\*\s*(\d+)\s*" + cl) if engine.arithmeticFmt else None
        divZero = TestEngineMatrix._DIVZERO
        err = errors.get(engine.name)

        def server(place, parameter, value):
            # 1) engine-specific distinguishing probe
            if engine.distinguishingProbe and engine.distinguishingProbe in value:
                if engine.distinguishingResult:
                    return "Hello " + engine.distinguishingResult
                return "Hello"          # comment-style probe -> stays at baseline
            # 2) this engine's own boolean rendering
            if engine.booleanTrue and engine.booleanTrue in value:
                return "Hello " + engine.trueRendered
            if engine.booleanFalse and engine.booleanFalse in value:
                return "Hello " + engine.falseRendered
            # 3) divide-by-zero -> language-family-specific error (S2), for engines that evaluate it
            if arithRe is not None and (engine.delimiter + "1/0" + engine.delimiterClose) in value:
                return divZero.get(engine.family, "Hello")
            # 4) arithmetic, but ONLY for engines that actually evaluate it
            if arithRe is not None:
                m = arithRe.search(value)
                if m:
                    return "Hello %d" % (int(m.group(1)) * int(m.group(2)))
            # 5) malformed fragment in this engine's delimiter -> engine-specific error
            if err and any(p in value for p in engine.errorProbes):
                return err
            # 6) anything else (incl. other engines' payloads) renders inertly
            return "Hello"

        return server

    def test_every_engine_is_fingerprinted(self):
        for engine in ssti._ENGINE_TABLE:
            ssti._send = self._make_server(engine, self._ERRORS)
            result, evidence = ssti._fingerprint("GET", "q")
            self.assertIsNotNone(result, "engine '%s' was not detected at all" % engine.name)
            self.assertIn(engine.name, result.name,
                "server running '%s' was identified as '%s'" % (engine.name, result.name))

    def test_family_probe_confirms_language(self):
        # S2: the divide-by-zero probe must confirm the backend family for every
        # expression-evaluating, non-JS engine (Python/Ruby/PHP/Java).
        for engine in ssti._ENGINE_TABLE:
            if not (engine.arithmeticFmt and engine.delimiterClose):
                continue
            if engine.family not in ("python", "ruby", "php", "java"):
                continue
            ssti._send = self._make_server(engine, self._ERRORS)
            _result, evidence = ssti._fingerprint("GET", "q")
            self.assertTrue(evidence.get("family"),
                "family probe should confirm '%s' on a %s backend" % (engine.name, engine.family))

    def test_filter_evasion_rce_fallbacks_present(self):
        # S3: each engine must retain its filter-evasion / sandbox-escape RCE fallbacks.
        def rce(name):
            return " ".join(p for p, _d in next(e for e in ssti._ENGINE_TABLE if e.name == name).rcePayloads)
        jinja = rce("Jinja2")
        self.assertIn("attr(", jinja)                       # dot/underscore-free attr() chain
        self.assertIn("\\x5f", jinja)                       # hex-escaped dunders
        twig = rce("Twig")
        self.assertIn("sort('system')", twig)
        self.assertIn("map('system')", twig)
        spring = rce("Spring EL / Thymeleaf")
        self.assertIn("readLine", spring)                   # output-capturing SpEL
        self.assertIn("@java.lang.Runtime@getRuntime", spring)   # OGNL fallback

    def test_family_probe_does_not_crossmatch(self):
        # Python 'division by zero' must NOT satisfy the (case-sensitive) PHP signature, so a
        # Jinja2/Python server never lets Twig/PHP claim a family match.
        jinja = next(e for e in ssti._ENGINE_TABLE if e.name == "Jinja2")
        ssti._send = self._make_server(jinja, self._ERRORS)
        cache = {}
        twig = next(e for e in ssti._ENGINE_TABLE if e.name == "Twig")
        self.assertEqual(ssti._probeFamily("GET", "q", jinja, cache), "python")
        self.assertNotEqual(ssti._probeFamily("GET", "q", twig, cache), twig.family)

    def test_erb_arithmetic_works_after_format_fix(self):
        # Direct regression guard for the '<%= %d*%d %>' / '<%= %s %>' format bug.
        erb = next(e for e in ssti._ENGINE_TABLE if e.name == "ERB")
        ssti._send = self._make_server(erb, self._ERRORS)
        self.assertTrue(ssti._probeArithmetic("GET", "q", erb),
            "ERB arithmetic proof must succeed once %-format no longer crashes on '%>'")
        result, evidence = ssti._fingerprint("GET", "q")
        self.assertEqual(result.name, "ERB")
        self.assertTrue(evidence.get("arithmetic"))

    def test_mako_distinguished_from_freemarker_spring(self):
        # Mako shares '${ }' with Freemarker/Spring but renders capital True/False;
        # it must be named exactly (via unique boolean rendering), not "probable".
        mako = next(e for e in ssti._ENGINE_TABLE if e.name == "Mako")
        ssti._send = self._make_server(mako, self._ERRORS)
        result, evidence = ssti._fingerprint("GET", "q")
        self.assertEqual(result.name, "Mako")
        self.assertTrue(evidence.get("boolean"))
