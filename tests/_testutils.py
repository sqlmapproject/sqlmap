#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Shared bootstrap for the sqlmap unit/regression test suite.

Brings sqlmap's global state (conf/kb, the 'reversible' codec, cross-references,
option defaults) up far enough that pure/near-pure library functions can be
exercised in isolation - WITHOUT a live target, network, or DBMS.

stdlib unittest only (no pytest / no pip); works on Python 2.7 and 3.x.
"""

import os
import sys
import warnings

# Quieten import-time noise before any sqlmap/3rd-party module is imported by bootstrap():
# e.g. cryptography's "Python 2 is no longer supported" CryptographyDeprecationWarning via pymysql.
warnings.filterwarnings("ignore", message=".*Python 2 is no longer supported.*")
warnings.filterwarnings("ignore", category=DeprecationWarning)
# sqlmap reconfigures stdout at startup; py3 emits a benign RuntimeWarning about line buffering
warnings.filterwarnings("ignore", message=".*line buffering.*binary mode.*")

_BOOTSTRAPPED = False
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def bootstrap():
    """Idempotently initialize sqlmap global state for testing."""
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return

    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    # a dummy target so cmdLineParser() populates ALL option defaults without erroring;
    # save/restore the real argv so the unittest runner isn't confused by it
    _orig_argv = list(sys.argv)
    sys.argv = ["sqlmap.py", "-u", "http://test.invalid/?id=1"]

    from lib.core.common import setPaths
    from lib.core.patch import dirtyPatches, resolveCrossReferences
    setPaths(ROOT)
    dirtyPatches()                 # registers the 'reversible' codec error handler, etc.
    resolveCrossReferences()

    from lib.core.option import _setConfAttributes, _setKnowledgeBaseAttributes, _loadQueries
    _setConfAttributes()
    _setKnowledgeBaseAttributes()
    _loadQueries()                 # populate the `queries` dict from queries.xml (needed by dialect builders)

    from lib.core.data import conf, kb
    from lib.core.defaults import defaults
    from lib.parse.cmdline import cmdLineParser

    args = cmdLineParser()
    parsed = args.__dict__ if hasattr(args, "__dict__") else dict(args)
    for k, v in parsed.items():
        conf[k] = v
    # overlay canonical defaults for options left None (sqlmap does this during init)
    for k, v in defaults.items():
        if conf.get(k) is None:
            conf[k] = v

    kb.binaryField = False         # normally set lazily during extraction

    # Silence sqlmap's application logger - tests assert on results, not log output, and the
    # INFO/WARNING/ERROR chatter (column counts, reflective-value notices, an intentionally
    # malformed-deflate error, etc.) just clutters the unittest report.
    import logging
    logging.getLogger("sqlmapLog").setLevel(logging.CRITICAL + 1)

    # Some console output bypasses the logger entirely and goes straight through dataToStdout():
    # the \r-progress lines ("[INFO] retrieved: ...", "[INFO] cracked password ..."), and the echo
    # of batch-auto-answered readInput() prompts (the fingerprint-mismatch prompt, the LIKE/exact
    # and common-wordlist choices, ...). dataToStdout() only writes forced output or when
    # kb.wizardMode is False, and readInput() echoes with forceOutput=not kb.wizardMode - so setting
    # wizardMode keeps the unittest report to just dots. wizardMode is read ONLY by dataToStdout/
    # readInput (plus the interactive wizard flow, unused here), so this has no effect on results.
    kb.wizardMode = True

    sys.argv = _orig_argv          # restore so unittest's arg parsing works
    _BOOTSTRAPPED = True


def set_dbms(name):
    """Force the identified back-end DBMS for dialect-dependent functions.

    Uses forceDbms (not setDbms) so switching DBMS repeatedly in one process does
    not trigger the interactive fingerprint-mismatch prompt.
    """
    from lib.core.common import Backend
    from lib.core.data import kb
    kb.stickyDBMS = False
    Backend.forceDbms(name)


# --- property/fuzz testing harness (shared so individual test files don't each reinvent it) ---

_PROPERTY_BASE = 0x51A1


class Rng(object):
    """Deterministic, cross-version-identical PRNG (a pure-integer LCG, no global state).

    sqlmap runs on Python 2.7 and 3.x, whose stdlib `random` yield DIFFERENT sequences
    for the same seed - and `random.Random` instance methods are not unified by
    patch.unisonRandom() (which only patches the module-level random.choice/randint/
    sample/seed). Property tests need inputs that are byte-for-byte identical on every
    interpreter so a CI-only failure reproduces everywhere; integer math is identical
    across versions, so this LCG (same constants as unisonRandom) guarantees it by
    construction. Draw ONLY through these methods - never random.random()/shuffle()/etc.
    """

    def __init__(self, seed):
        self.x = seed & 0xFFFFFF

    def _next(self):
        self.x = (1140671485 * self.x + 128201163) % (2 ** 24)
        return self.x

    def randint(self, a, b):
        return a + self._next() % (b - a + 1)

    def choice(self, seq):
        return seq[self.randint(0, len(seq) - 1)]

    def sample(self, seq, k):
        # Note: with replacement (matches unisonRandom's _sample); fine for input generation
        return [self.choice(seq) for _ in range(k)]

    def blob(self, n):
        return bytes(bytearray(self.randint(0, 255) for _ in range(n)))


def _label_offset(label):
    # stable across versions/runs (unlike hash(), which varies with PYTHONHASHSEED): just sum bytes
    return sum(bytearray((label or "").encode("utf-8"))) * 7919


def for_all(testcase, generator, prop, n=400, label=""):
    """Property runner: draw `n` cases from generator(rng) and assert prop(case) holds.

    `prop` passes by returning True/None, fails by returning False or raising. On any
    failure the EXACT offending input and its case index are reported; the same input
    is reproducible (and identical on every interpreter) via Rng(seed_for(label, i)).
    """
    base = _PROPERTY_BASE + _label_offset(label)
    for i in range(n):
        case = generator(Rng(base + i))
        try:
            ok = prop(case)
        except Exception as ex:
            testcase.fail("%s: raised %r on input %r (case %d)" % (label or "property", ex, case, i))
            return
        if ok is False:
            testcase.fail("%s: property does not hold on input %r (case %d)" % (label or "property", case, i))
            return
