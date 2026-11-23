#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import difflib

from lib.core.compat import xrange
from lib.core.common import getFileItems
from lib.core.common import paramToDict
from lib.core.common import randomStr
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import HTTPMETHOD
from lib.core.enums import PLACE
from lib.core.settings import DIFF_TOLERANCE
from lib.core.settings import MAX_DIFFLIB_SEQUENCE_LENGTH
from lib.core.settings import PARAMETER_MINING_BUCKET_SIZE
from lib.request.connect import Connect as Request

# Benign, broadly-stable value used both to check whether a discovered parameter is safe to add and
# as its seed during testing (a random value would error out an integer/id context and defeat inference)
PROBE_VALUE = "1"

def _canary():
    return randomStr(10, lowercase=True)

def _fetch(get):
    """
    Requests the target with the given GET query string, returning a (page, HTTP code) pair.
    """

    try:
        page, _, code = Request.getPage(get=get or None, silent=True, raise404=False)
    except Exception:
        page, code = None, None

    return (page or ""), code

def _ratio(first, second):
    """
    Similarity of two response bodies, mirroring the core page comparison (see comparison.py): an
    exact match, a length ratio for oversized bodies, otherwise difflib's quick_ratio().
    """

    if not first or not second:
        return 0.0

    if first == second:
        return 1.0

    if any(len(_) > MAX_DIFFLIB_SEQUENCE_LENGTH for _ in (first, second)):
        ratio = 1.0 * len(first) / len(second)
        return ratio if ratio <= 1 else 1.0 / ratio

    return difflib.SequenceMatcher(None, first, second).quick_ratio()

def _differs(page, base, floor):
    """
    True when 'page' departs from the baseline by more than the target's own dynamic jitter ('floor').
    """

    return bool(page) and _ratio(page, base) < floor - DIFF_TOLERANCE

def _confirm(baseGet, name, base, floor):
    """
    Confirms a single candidate in isolation with two differently-valued probes. Returns 'reflected'
    when a value is echoed back (caught here even if a shared bucket hid it behind a preceding
    parameter), 'behavioral' when both probes resemble each other yet depart from the baseline (its
    presence, not its value, matters), otherwise None.
    """

    def _get(value):
        pair = "%s=%s" % (name, value)
        return "%s&%s" % (baseGet, pair) if baseGet else pair

    canaries = (_canary(), _canary())
    first, second = _fetch(_get(canaries[0]))[0], _fetch(_get(canaries[1]))[0]

    if not (first and second):
        return None

    if (canaries[0] in first or canaries[1] in second) and not any(_ in base for _ in canaries):
        return "reflected"

    if _ratio(first, second) < floor - DIFF_TOLERANCE:      # value-dependent yet not reflected -> unreliable
        return None

    if _differs(first, base, floor) and _differs(second, base, floor):
        return "behavioral"

    return None

def _chunks(sequence, size):
    for i in xrange(0, len(sequence), size):
        yield sequence[i:i + size]

def _discover(candidates, baseGet, base, floor):
    """
    Probes candidate names in buckets (one shared request per bucket, each name carrying its own
    random canary) and returns the confirmed ones as (name, reason) pairs. Reflection is resolved
    straight from the bucket response; the rest are confirmed individually only when the bucket
    actually moved the response, so a target that ignores every candidate stays cheap.
    """

    found = []

    for chunk in _chunks(candidates, PARAMETER_MINING_BUCKET_SIZE):
        canaries = dict((name, _canary()) for name in chunk)
        query = "&".join("%s=%s" % (name, canaries[name]) for name in chunk)
        page = _fetch("%s&%s" % (baseGet, query) if baseGet else query)[0]

        if not page:
            continue

        pending = []
        for name in chunk:
            if canaries[name] in page and canaries[name] not in base:
                found.append((name, "reflected"))
            else:
                pending.append(name)

        if pending and _differs(page, base, floor):
            for name in pending:
                reason = _confirm(baseGet, name, base, floor)
                if reason:
                    found.append((name, reason))

    return found

def _commit(found, baseGet, baseCode):
    """
    Adds the discovered parameters (seeded with PROBE_VALUE) to the GET test scope. One that turns
    the request into a server error the baseline did not have would shadow and corrupt the testing
    of every sibling parameter, so it is reported and held back rather than degrading detection.
    """

    safe, disruptive = [], []

    for name, _ in found:
        pair = "%s=%s" % (name, PROBE_VALUE)
        code = _fetch("%s&%s" % (baseGet, pair) if baseGet else pair)[1]
        if code is not None and code >= 500 and not (baseCode is not None and baseCode >= 500):
            disruptive.append(name)
        else:
            safe.append(name)

    if disruptive:
        logger.warning("held back parameter(s) that break the base request with a test value (test them explicitly with '-p'): %s" % ", ".join("'%s'" % _ for _ in disruptive))

    if not safe:
        return

    logger.info("adding %d discovered parameter(s) to the test scope: %s" % (len(safe), ", ".join("'%s'" % _ for _ in safe)))

    additions = "&".join("%s=%s" % (name, PROBE_VALUE) for name in safe)
    conf.parameters[PLACE.GET] = "%s&%s" % (baseGet, additions) if baseGet else additions
    conf.paramDict[PLACE.GET] = paramToDict(PLACE.GET, conf.parameters[PLACE.GET])

def mineParameters():
    """
    Discovers hidden (unlinked) GET parameters the target still processes and queues the confirmed
    ones for the regular injection tests, using two independent oracles (value reflection and a
    behavioral side effect on the response).
    """

    if conf.data or (conf.method and conf.method != HTTPMETHOD.GET):
        singleTimeWarnMessage("'--mine-params' currently supports GET parameters only")
        return

    baseGet = conf.parameters.get(PLACE.GET) or ""
    existing = set(conf.paramDict.get(PLACE.GET) or {})
    candidates = [_ for _ in getFileItems(paths.COMMON_PARAMETERS, unique=True) if _ and _ not in existing]

    if not candidates:
        return

    logger.info("mining for hidden GET parameters (%d candidate name(s))" % len(candidates))

    base, baseCode = _fetch(baseGet)
    if not base:
        singleTimeWarnMessage("could not obtain a baseline response, skipping parameter mining")
        return

    jitter = _fetch(baseGet)[0]
    floor = _ratio(base, jitter) if jitter else 1.0     # the target's own between-request jitter; an unanswered probe leaves it unmeasured, so assume none (_ratio() would say 0.0, which turns _differs() off for the whole run)

    found = _discover(candidates, baseGet, base, floor)

    for name, reason in found:
        logger.info("found hidden parameter '%s' (%s)" % (name, reason))

    if not found:
        logger.info("no hidden parameters found")
        return

    _commit(found, baseGet, baseCode)
