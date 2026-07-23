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

    def test_struts2_ognl_arithmetic_control_pair(self):
        # Struts2 evaluates '%{expr}' (OGNL) and reflects it in the redisplayed field value
        engine = [e for e in ssti._ENGINE_TABLE if e.name == "Struts2 (OGNL)"][0]

        def mock(place, parameter, value):
            import re
            m = re.search(r"%\{(\d+)\*(\d+)\}", value)
            if m:
                return 'name="username" value="%d"' % (int(m.group(1)) * int(m.group(2)))
            return 'name="username" value="%s"' % value

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

    def test_ssti_static_engine_error_is_not_confirmation(self):
        # a static template-parser error (present for every value, no arithmetic/boolean evaluation
        # proof) must NOT confirm SSTI - only reflect the payload and always leak an engine name
        def mock(place, parameter, value):
            return "debug: jinja2.exceptions.TemplateSyntaxError (cached). you sent: " + value
        ssti._send = mock
        engine, evidence = ssti._fingerprint("GET", "q")
        self.assertIsNone(engine)   # no evaluation proof -> not a confirmed SSTI

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

    def test_true_marker_in_baseline_rejected(self):
        """When the true marker ('True') is already present in the untouched baseline it is page
        furniture, not our evaluated output, so its appearance cannot confirm a boolean oracle."""
        engine = ssti._ENGINE_TABLE[0]  # Jinja2, trueRendered='True'

        def mock(place, parameter, value):
            if "{{ True }}" in value:
                return "flag=True ok"
            if "{{ False }}" in value:
                return "flag=True no"       # diverges, but 'True' still shown
            return "flag=True baseline"     # 'True' already in the baseline

        ssti._send = mock
        self.assertIsNone(ssti._detectBoolean("GET", "q", engine))

    def test_error_pages_are_not_a_boolean_oracle(self):
        """Two syntactically invalid true/false payloads that merely trip DIFFERENT engine error
        messages diverge, but an error page is not a rendered boolean -> no oracle."""
        engine = ssti._ENGINE_TABLE[0]  # Jinja2

        def mock(place, parameter, value):
            if "{{ True }}" in value:
                return "jinja2.exceptions.UndefinedError: x"
            if "{{ False }}" in value:
                return "TemplateSyntaxError: y"
            return "baseline"

        ssti._send = mock
        self.assertIsNone(ssti._detectBoolean("GET", "q", engine))


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


class TestRceProof(unittest.TestCase):
    """Proof-of-execution via a DERIVED challenge: reflection (raw OR transformed) must NOT be accepted."""

    def setUp(self):
        self.original_send = ssti._send

    def tearDown(self):
        ssti._send = self.original_send

    def test_derived_executed_needs_product_absent_from_request(self):
        # the product proves execution: present in the page, absent from baseline
        self.assertTrue(ssti._derivedExecuted("page 6772561 footer", "baseline", "6772561"))
        self.assertIsNone(ssti._derivedExecuted("page without it", "baseline", "6772561"))
        # product already in baseline -> not attributable
        self.assertIsNone(ssti._derivedExecuted("x 6772561 x", "seen 6772561 here", "6772561"))

    def test_probe_rce_rejects_raw_reflection(self):
        # an app that echoes the whole request body verbatim: the product ($((A*B)) result) is NEVER in
        # the request, so it cannot appear in a reflected response -> not RCE-capable
        engine = ssti._ENGINE_TABLE[0]  # Jinja2 (no _FILE_RCE spec -> file path is a no-op)
        ssti._send = lambda place, parameter, value: "Hello, %s!" % value   # pure reflection
        self.assertFalse(ssti._probeRce("GET", "q", engine))

    def test_probe_rce_rejects_url_encoded_reflection(self):
        # KEY P0-4 case: the app reflects the URL-ENCODED payload. A marker-in-payload check would pass;
        # the derived product is still absent from any reflected form -> correctly NOT RCE-capable
        from thirdparty.six.moves.urllib.parse import quote
        engine = ssti._ENGINE_TABLE[0]
        ssti._send = lambda place, parameter, value: "reflected: %s" % quote(value, safe="")
        self.assertFalse(ssti._probeRce("GET", "q", engine))

    def test_probe_rce_all_collisions_do_not_confirm(self):
        # every generated product collides with the baseline -> every challenge is skipped; the loop
        # must NOT fall through to success with zero executed payloads (counts confirmations, not iters)
        engine = ssti._ENGINE_TABLE[0]
        import lib.techniques.ssti.inject as _m
        orig = _m.randomInt
        try:
            _m.randomInt = lambda n: 2                       # product is always 4
            ssti._send = lambda place, parameter, value: "result is 4 everywhere"   # baseline contains "4"
            self.assertFalse(ssti._probeRce("GET", "q", engine))
        finally:
            _m.randomInt = orig

    def test_probe_rce_confirms_real_execution(self):
        # a backend that actually evaluates `echo $((A*B))` returns the PRODUCT as command output
        engine = ssti._ENGINE_TABLE[0]
        import re as _re

        def mock(place, parameter, value):
            m = _re.search(r"echo \$\(\((\d+)\*(\d+)\)\)", value)
            if m:
                return "<html>%d</html>" % (int(m.group(1)) * int(m.group(2)))   # shell-evaluated product
            return "baseline"

        ssti._send = mock
        self.assertTrue(ssti._probeRce("GET", "q", engine))

    def test_framed_output_markers_are_reflection_proof(self):
        # markers are shell-concatenated fragments: the completed 'startABstartCD' never appears in the
        # request, so only genuine execution places them in the page
        start, end = "aaaaaabbbbbb", "ccccccdddddd"
        executed = "junk %suid=0(root) gid=0(root)%s junk" % (start, end)
        self.assertEqual(ssti._framedOutput(executed, start, end), "uid=0(root) gid=0(root)")
        # a response that lacks the concatenated markers (e.g. reflected 'aaaaaa bbbbbb' separated) -> None
        self.assertIsNone(ssti._framedOutput("printf %s%s aaaaaa bbbbbb ...", start, end))

    def test_probe_rce_confirms_on_windows_backend(self):
        # a Windows-hosted engine evaluates `cmd /c set /a A*B` (Unix `$((...))` does nothing) - the
        # derived product still proves execution, so capability detection works on Windows too
        engine = ssti._ENGINE_TABLE[0]
        import re as _re

        def mock(place, parameter, value):
            m = _re.search(r"set /a (\d+)\*(\d+)", value)        # cmd.exe set /a arithmetic
            if m and "$((" not in value:
                return "<html>%d</html>" % (int(m.group(1)) * int(m.group(2)))
            return "baseline"                                    # the Unix $(( )) family produces nothing here

        ssti._send = mock
        self.assertTrue(ssti._probeRce("GET", "q", engine))

    def test_windows_framed_builder_shape(self):
        # the Windows framed command concatenates the marker fragments at runtime via `echo|set /p=`
        cmd = ssti._winFramed("whoami", "SA", "SB", "EA", "EB")
        self.assertIn("cmd /c", cmd)
        self.assertIn("set /p=SA", cmd)
        self.assertIn("set /p=SB", cmd)
        self.assertIn("whoami", cmd)
        # the concatenated markers 'SASB'/'EAEB' are NOT present literally (only the separate fragments)
        self.assertNotIn("SASB", cmd)
        self.assertNotIn("EAEB", cmd)


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
        ssti.conf.dumper = self.original_dumper   # restore unconditionally (was None -> don't leak the mock dumper)

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
        """When all RCE payloads produce template errors, no success is reported. _executeCommand sends
        a baseline, then TWO passes over the payloads: a reflection-proof boundary-marker capture pass
        a framed pass PER OS family (unix + windows), and an unframed baseline-diff fallback pass (the
        file-based pass sends nothing without a _FILE_RCE spec, as for Jinja2)."""
        engine = ssti._ENGINE_TABLE[0]
        self.assertNotIn(engine.name, ssti._FILE_RCE)   # guard the arithmetic below
        calls = []

        def mock(place, parameter, value):
            calls.append(value)
            return "jinja2.exceptions.TemplateSyntaxError: unexpected token"

        ssti._send = mock
        ssti._executeCommand("GET", "q", engine, "test")
        # 1 baseline + (families framed + 1 unframed) passes, each over N payloads
        passes = len(ssti._SHELL_FAMILIES) + 1
        self.assertEqual(len(calls), 1 + passes * len(engine.rcePayloads),
            "Should have tried the framed pass per OS family then the unframed pass before giving up")


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


class TestFileBasedRce(unittest.TestCase):
    """Two-step file-based RCE fallback (_FILE_RCE) for JDK-hardened Java engines: modern JVMs
    reflectively block Process.getInputStream(), so in-band stdout capture errors out; exec-to-tempfile
    then read-file must still recover the command output."""

    def setUp(self):
        from lib.core.data import conf
        self._send = ssti._send
        self._dumper = conf.dumper
        captured = self.captured = []

        class _Dumper(object):
            def singleString(self, text, **kwargs):
                captured.append(text)

        conf.dumper = _Dumper()

    def tearDown(self):
        from lib.core.data import conf
        ssti._send = self._send
        conf.dumper = self._dumper

    def test_spel_output_via_file_when_inband_blocked(self):
        engine = next(e for e in ssti._ENGINE_TABLE if e.name == "Spring EL / Thymeleaf")
        self.assertIn(engine.name, ssti._FILE_RCE)   # engine wired for the two-step fallback

        def mock(place, parameter, value):
            if "ProcessBuilder" in value:                          # exec step: launches (render error, ignored)
                return "org.springframework.expression.spel.SpelEvaluationException: EL1001E"
            if "readAllBytes" in value:                            # read step: the temp file's content
                return "Hello uid=0(root) gid=0(root)"
            if "Runtime" in value or "getInputStream" in value:    # in-band capture blocked on hardened JDK
                return "org.springframework.expression.spel.SpelEvaluationException: EL1029E"
            return "Hello "                                        # baseline / original value

        ssti._send = mock
        ssti._executeCommand("GET", "q", engine, "id")
        self.assertTrue(any("uid=0(root)" in _ for _ in self.captured),
                        msg="two-step file-based RCE did not surface command output: %r" % self.captured)


class TestStruts2Header(unittest.TestCase):
    """CVE-2017-5638 (S2-045): OGNL via the Content-Type header. The vector is not reflected, so
    detection prints a marker to the response and RCE brackets stdout with markers to slice it out."""

    def setUp(self):
        self._s2045Send = ssti._s2045Send

    def tearDown(self):
        ssti._s2045Send = self._s2045Send

    def test_struts2_wired_for_file_rce(self):
        self.assertIn("Struts2 (OGNL)", ssti._FILE_RCE)   # modern-JDK file-based fallback wired

    def test_s2045_detection_derived_product(self):
        import re
        # a vulnerable Struts2 EVALUATES the OGNL arithmetic and writes the PRODUCT (absent from the header)
        def mock(url, action):
            m = re.search(r"#w\.print\((\d+)\*(\d+)\)", action)
            return "<html> %d </html>" % (int(m.group(1)) * int(m.group(2))) if m else "<html/>"
        ssti._s2045Send = mock
        self.assertTrue(ssti._probeStruts2Header("http://target"))

    def test_s2045_detection_rejects_reflected_header(self):
        # KEY P0-6 case: the server REFLECTS the Content-Type header verbatim. The literal operands are
        # echoed but never their product, so no reflection can satisfy the derived challenge -> not vuln
        ssti._s2045Send = lambda url, action: "You sent Content-Type: %s" % action
        self.assertIsNone(ssti._probeStruts2Header("http://target"))

    def test_s2045_not_vulnerable(self):
        ssti._s2045Send = lambda url, action: "<html>ordinary Struts page, no eval</html>"
        self.assertIsNone(ssti._probeStruts2Header("http://target"))

    def test_s2045_all_collisions_do_not_confirm(self):
        # every product collides with the baseline -> no challenge is ever evaluated -> not confirmed
        import lib.techniques.ssti.inject as _m
        orig = _m.randomInt
        try:
            _m.randomInt = lambda n: 2                       # product is always 4
            ssti._s2045Send = lambda url, action: "page containing 4"
            self.assertIsNone(ssti._probeStruts2Header("http://target"))
        finally:
            _m.randomInt = orig

    def test_s2045_command_output_sliced_from_derived_markers(self):
        import re
        # the shell CONCATENATES the marker fragments (printf %s%s A B -> AB); the concatenation never
        # appears in the header, so it can only come from execution
        def mock(url, action):
            m = re.search(r"printf %s%s (\w+) (\w+); .* 2>&1; printf %s%s (\w+) (\w+)", action)
            if not m:
                return "<html/>"
            start, end = m.group(1) + m.group(2), m.group(3) + m.group(4)
            return "<html>%s\nuid=0(root) gid=0(root)\n%s</html>" % (start, end)
        ssti._s2045Send = mock
        self.assertEqual(ssti._executeStruts2Header("http://target", "id"), "uid=0(root) gid=0(root)")

    def test_s2045_command_rejects_reflected_header(self):
        # raw header reflection: the fragments appear separated ('printf %s%s A B'), never concatenated,
        # so no start/end marker is found -> no fabricated 'output'
        ssti._s2045Send = lambda url, action: "reflected: %s" % action
        self.assertIsNone(ssti._executeStruts2Header("http://target", "id"))
