#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Shared detection primitives for the non-SQL injection techniques (--nosql, --xpath, --ldap, --hql,
--ssti, --graphql, --xxe). Each of those engines historically carried its own copy of the same
response-comparison, error/blocked-status filtering, blind-bit classification and user-oracle logic;
this module is the single home for that shared machinery so the behavior is uniform and reviewable
in one place rather than drifting across six files.
"""

import difflib
import re

from lib.core.data import conf
from lib.core.settings import UPPER_RATIO_BOUND
from lib.parse.html import htmlParser

# Minimum similarity margin by which a blind-extraction response must lean toward the confirmed TRUE
# model over the FALSE model before a bit is accepted as true (else ambiguous -> false). Deliberately
# generous: a small (e.g. 5%) margin lets a noisy page fabricate values one character at a time.
EXTRACT_MATCH_MARGIN = 0.2

# HTTP statuses that mean the response is BLOCKED (WAF / rate-limit); together with 5xx these must
# never be fed to a boolean oracle as if they were application content.
BLOCKED_HTTP_CODES = frozenset((403, 429))

# generic SQL/DBMS error marker (mirrors lib/parse/html.py's own generic check), used alongside the
# DBMS-specific errors.xml signatures that htmlParser() recognizes
_SQL_ERROR_REGEX = re.compile(r"(?i)SQL (warning|error|syntax)")


def ratio(first, second):
    """Content-similarity ratio shared by every non-SQL detector (difflib quick_ratio over the two
    response bodies) - one implementation instead of six identical copies."""
    return difflib.SequenceMatcher(None, first or "", second or "").quick_ratio()


def blockedStatus(code):
    """True when an HTTP status means the response is blocked/errored (a 5xx, or a WAF/rate-limit
    403/429) and so is not a usable oracle sample. `_send()` implementations return None for these
    (and for transport exceptions) so the boolean routines, which reject None, can never decide on
    a non-answer."""
    return bool(code) and (code >= 500 or code in BLOCKED_HTTP_CODES)


def sqlErrorPresent(page):
    """True when the response carries a recognized SQL/DBMS error - either a DBMS-specific signature
    from sqlmap's errors.xml (via htmlParser) or the generic 'SQL warning/error/syntax' marker. The
    non-SQL detectors treat such a page as NOT a valid boolean template, so a payload that merely
    trips a back-end SQL syntax error cannot fake a true/false divergence and get a plainly SQL-
    injectable parameter mis-reported as NoSQL / XPath / LDAP / HQL."""
    page = page or ""
    return bool(htmlParser(page)) or bool(_SQL_ERROR_REGEX.search(page))


# Visible placeholder for a single recovered cell/attribute whose extraction was INCONCLUSIVE (the
# oracle stayed ambiguous after retries). Rendered in dumps in place of the value so a failed cell is
# never silently shown as a genuine empty string - `None` from an extractor means "unknown", `""` means
# "really empty", and they must stay distinguishable in the output.
INCONCLUSIVE_MARK = "<inconclusive>"


class InconclusiveError(Exception):
    """Raised by resolveBit(abort=True) when a bit stays INCONCLUSIVE after retries. Per-value
    extractors catch it to ABORT the current value (return what was recovered so far, marked
    incomplete) instead of substituting a semantic False - which would corrupt a length, pick the
    wrong half of a bisection, or truncate enumeration."""


class Decision(object):
    """Tri(+)-state blind-inference outcome. INCONCLUSIVE is deliberately DISTINCT from FALSE: an
    ambiguous comparison (equally close to both models, close to neither, or a transport/blocked
    anomaly) must be retried/aborted, NOT silently read as a semantic false - which would shorten a
    value, pick the wrong half of a bisection or truncate enumeration."""
    TRUE = "TRUE"
    FALSE = "FALSE"
    INCONCLUSIVE = "INCONCLUSIVE"


def decide(page, trueModel, falseModel, margin=EXTRACT_MATCH_MARGIN):
    """Classify a blind-inference response against the two calibrated models, returning a Decision.
    TRUE when it resembles the confirmed TRUE model (identical, or clearly closer to it than to the
    FALSE model by `margin`); FALSE when it resembles the FALSE model; INCONCLUSIVE when it leans to
    neither (so the caller can retry or abort rather than guess)."""
    if page is None:
        return Decision.INCONCLUSIVE
    simTrue, simFalse = ratio(trueModel, page), ratio(falseModel, page)
    if simTrue >= UPPER_RATIO_BOUND and simTrue >= simFalse:
        return Decision.TRUE
    if simFalse >= UPPER_RATIO_BOUND and simFalse >= simTrue:
        return Decision.FALSE
    if (simTrue - simFalse) >= margin:
        return Decision.TRUE
    if (simFalse - simTrue) >= margin:
        return Decision.FALSE
    return Decision.INCONCLUSIVE


def resolveBit(page, trueModel, falseModel, resend, retries=2, margin=EXTRACT_MATCH_MARGIN, abort=True):
    """Resolve one blind bit to True/False. On an INCONCLUSIVE first read, RE-SEND (fresh, cache-
    bypassing) up to `retries` times to ride out transient jitter before deciding. `resend` is a
    0-arg callable returning a fresh page (or None on error/block). If a bit stays INCONCLUSIVE after
    the retries: raise InconclusiveError when `abort` (the caller aborts the CURRENT VALUE rather than
    corrupt it), else return False."""
    d = decide(page, trueModel, falseModel, margin)
    tries = 0
    while d is Decision.INCONCLUSIVE and tries < retries:
        page = resend()
        if page is None:
            break
        d = decide(page, trueModel, falseModel, margin)
        tries += 1
    if d is Decision.INCONCLUSIVE and abort:
        raise InconclusiveError()
    return d is Decision.TRUE


def leansTrue(page, trueModel, falseModel, margin=EXTRACT_MATCH_MARGIN):
    """Boolean shorthand for `decide(...) is Decision.TRUE` (kept for callers that don't retry).
    A page indistinguishable from the FALSE model, or ambiguous, is NOT true - so a dynamic token, a
    changed error page, a WAF/rate-limit body or a transient exception can never fabricate a bit."""
    return decide(page, trueModel, falseModel, margin) is Decision.TRUE


def userOracleActive():
    """True when the user supplied an explicit true/false response signal (--string / --not-string /
    --regexp) that the non-SQL techniques should honor instead of relying on raw page similarity."""
    return bool(getattr(conf, "string", None) or getattr(conf, "notString", None) or getattr(conf, "regexp", None))


def userDecision(page):
    """Classify a response with the user's explicit oracle (--string / --not-string / --regexp),
    returning True/False, or None when no override is set (caller falls back to content comparison).
    Page-only: HTTP-code overrides (--code) stay per-engine, where the status line is available.

    This routes the non-SQL boolean detectors through sqlmap's documented detection overrides - the
    same knobs the SQL engine honors - rather than discarding them for a fixed similarity ratio."""
    page = page or ""
    if getattr(conf, "string", None):
        return conf.string in page
    if getattr(conf, "notString", None):
        return conf.notString not in page
    if getattr(conf, "regexp", None):
        return re.search(conf.regexp, page) is not None
    return None
