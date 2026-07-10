#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.PGSQL))

def tamper(payload, **kwargs):
    """
    Replaces single-quoted strings with PostgreSQL dollar-quoted strings (e.g. 'abc' -> $$abc$$)

    Requirement:
        * PostgreSQL

    Tested against:
        * PostgreSQL 9.x, 10-16

    Notes:
        * Useful to bypass filters that block, strip or escape the single-quote
          character: dollar-quoting is quote-free and needs no escaping
        * A literal already containing '$$' is left untouched

    >>> tamper("SELECT 'abc' FROM t WHERE x='def'")
    'SELECT $$abc$$ FROM t WHERE x=$$def$$'
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"'([^']*)'", lambda match: "$$%s$$" % match.group(1) if "$$" not in match.group(1) else match.group(0), payload)

    return retVal
