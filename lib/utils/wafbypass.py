#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import base64
import json
import os
import struct
import sys

from lib.core.common import fetchRandomAgent
from lib.core.data import conf
from lib.core.data import paths
from lib.core.enums import HTTP_HEADER
from lib.core.enums import PLACE
from lib.core.settings import WAF_BYPASS_HTTP_HEADERS
from lib.core.settings import WAF_BYPASS_TAMPERS


def neutralizeFingerprint():
    """
    Makes the request look like a real browser (random non-scanner User-Agent from the canonical
    'txt/user-agents.txt' - the same source as switch '--random-agent' - plus browser Accept/Accept-Language),
    used by automatic WAF-bypass. The per-request User-Agent is sourced from conf.parameters[PLACE.USER_AGENT]
    (queryPage passes it explicitly, overriding conf.agent), so that is the authoritative knob; conf.agent
    and the HTTP header list are updated too. Returns the previous state so the change can be reverted.
    """

    saved = (conf.agent, conf.httpHeaders, conf.parameters.get(PLACE.USER_AGENT))

    userAgent = fetchRandomAgent()

    conf.agent = userAgent
    if PLACE.USER_AGENT in conf.parameters:
        conf.parameters[PLACE.USER_AGENT] = userAgent

    overrides = dict(((HTTP_HEADER.USER_AGENT, userAgent),) + tuple(WAF_BYPASS_HTTP_HEADERS))
    upper = dict((_.upper(), _) for _ in overrides)
    headers, seen = [], set()
    for header, hvalue in conf.httpHeaders:
        if header.upper() in upper:
            headers.append((header, overrides[upper[header.upper()]]))
            seen.add(header.upper())
        else:
            headers.append((header, hvalue))
    for header, hvalue in overrides.items():
        if header.upper() not in seen:
            headers.append((header, hvalue))
    conf.httpHeaders = headers

    return saved

# identYwaf encodes each fingerprint as a packed array of 16-bit words, one per provocation
# vector, where the LOW bit marks whether that vector was blocked (lib/../identywaf/identYwaf.py:
# struct.pack(">H", (hash << 1) | blocked)). Decoding the bundled per-WAF signatures therefore
# yields, for free, which constructs a known WAF actually blocks - an empirical prior for picking
# bypass tampers. The two indices below (from data.json "payloads") are the ones we key decisions
# on: comment-obfuscated payloads (whether comment-insertion tampers stand any chance).
_IDENTYWAF_COMMENT_VECTORS = (2, 3, 13)   # "1/**/AND/**/1", "1/*0AND*/1", "1/**/UNION/**/SELECT.../information_schema.*"

_DATA = None


def _data():
    global _DATA
    if _DATA is None:
        path = os.path.join(paths.SQLMAP_ROOT_PATH, "thirdparty", "identywaf", "data.json")
        with open(path, "rb") as f:
            _DATA = json.loads(f.read().decode("utf-8"))
    return _DATA


def identYwafBlockedVectors(wafName):
    """
    Returns the set of provocation-vector indices that the given (identYwaf) WAF blocks, decoded
    from its bundled blind signatures (majority vote across signature variants). Empty set if the
    WAF/signatures are unknown.

    >>> isinstance(identYwafBlockedVectors("cloudflare"), set)
    True
    """

    retVal = set()

    wafs = _data().get("wafs", {})
    info = wafs.get(wafName) or wafs.get((wafName or "").lower())
    if not info:
        return retVal

    expected = len(_data().get("payloads", []))
    counts, total = {}, 0
    for signature in info.get("signatures", []):
        try:
            raw = base64.b64decode(signature.split(':', 1)[-1])
        except Exception:
            continue
        words = struct.unpack(">%dH" % (len(raw) // 2), raw) if len(raw) >= 2 else ()
        if len(words) != expected:                  # only consider signatures over the current vector set
            continue
        total += 1
        for index, word in enumerate(words):
            if word & 1:
                counts[index] = counts.get(index, 0) + 1

    if total:
        retVal = set(index for index, c in counts.items() if c * 2 >= total)   # blocked in a majority of variants

    return retVal


def candidateTampers(identifiedWafs=None):
    """
    Returns the ordered list of candidate tamper-script names for automatic WAF bypass: the
    empirically-ranked WAF_BYPASS_TAMPERS, with comment-insertion camouflage pruned when the
    identified WAF is known to block comment-obfuscated payloads (so requests aren't wasted on
    tampers that can't help). Semantics (and DBMS compatibility) are verified at runtime by
    re-running detection through each candidate, so no DBMS pre-filtering is needed here.

    >>> "between" in candidateTampers()
    True
    >>> "equaltolike" in candidateTampers()
    True
    """

    retVal = list(WAF_BYPASS_TAMPERS)

    blocked = set()
    for waf in (identifiedWafs or []):
        blocked |= identYwafBlockedVectors(waf)

    if blocked and any(_ in blocked for _ in _IDENTYWAF_COMMENT_VECTORS):
        retVal = [_ for _ in retVal if not _.startswith("space2") and _ != "versionedkeywords"]

    return retVal


def loadTamper(name):
    """
    Imports a tamper script by name from the tamper directory and returns its 'tamper' function
    (or None if missing). Mirrors the loader in option._setTamperingFunctions, for runtime use.
    """

    dirname = paths.SQLMAP_TAMPER_PATH
    if dirname not in sys.path:
        sys.path.insert(0, dirname)

    module = __import__(str(name))
    function = getattr(module, "tamper", None)
    if function is not None:
        function.__name__ = name

    return function
