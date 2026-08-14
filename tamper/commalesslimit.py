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

__priority__ = PRIORITY.HIGH

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    """
    Replaces (MySQL) instances like 'LIMIT M, N' with 'LIMIT N OFFSET M' counterpart

    Requirement:
        * MySQL
        * MariaDB
        * SQLite

    Tested against:
        * MySQL 8.4.9
        * MariaDB 11.8.8
        * SQLite 3.45.1

    Notes:
        * Applicability is set by the 'LIMIT M, N' input form, which only MySQL,
          MariaDB and SQLite accept. PostgreSQL rejects it (it takes solely the
          'LIMIT N OFFSET M' form this script produces), so the script never has
          anything to rewrite there

    >>> tamper('LIMIT 2, 3')
    'LIMIT 3 OFFSET 2'
    """

    retVal = payload

    match = re.search(r"(?i)LIMIT\s*(\d+),\s*(\d+)", payload or "")
    if match:
        retVal = retVal.replace(match.group(0), "LIMIT %s OFFSET %s" % (match.group(2), match.group(1)))

    return retVal
