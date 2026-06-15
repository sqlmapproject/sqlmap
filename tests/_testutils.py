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
