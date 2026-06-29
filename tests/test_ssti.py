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


class TestExpressionEvaluation(unittest.TestCase):
    def setUp(self):
        self.original_send = ssti._send

    def tearDown(self):
        ssti._send = self.original_send

    def test_eval_uses_expressionFmt(self):
        engine = ssti._ENGINE_TABLE[0]  # Jinja2: expressionFmt = "{{ %s }}"
        results = []

        def mock(place, parameter, value):
            results.append(value)
            return "Hello __marker__ 49 __marker2__"

        ssti._send = mock
        ssti._evalExpression("GET", "q", engine, "7*7")
        # Payload must use expressionFmt, not raw delimiter concatenation
        self.assertIn("{{ ", results[0])
        self.assertIn(" }}", results[0])

    def test_eval_falls_back_when_no_expressionFmt(self):
        engine = [e for e in ssti._ENGINE_TABLE if e.name == "Handlebars"][0]
        self.assertEqual(engine.expressionFmt, "")

        def mock(place, parameter, value):
            return "irrelevant"

        ssti._send = mock
        # Should not raise; just logs error
        ssti._evalExpression("GET", "q", engine, "7*7")


class TestBooleanUniqueness(unittest.TestCase):
    def test_jinja2_boolean_unique_among_curlies(self):
        jinja2 = ssti._ENGINE_TABLE[0]
        self.assertTrue(ssti._booleanUniquelyIdentifies(jinja2))

    def test_freemarker_boolean_not_unique(self):
        freemarker = [e for e in ssti._ENGINE_TABLE if e.name == "Freemarker"][0]
        # Freemarker and SpringEL both use ("${}", "true", "false") signature
        self.assertFalse(ssti._booleanUniquelyIdentifies(freemarker))

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
