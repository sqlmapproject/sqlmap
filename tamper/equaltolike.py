#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is unlikely to work against %s" % (os.path.basename(__file__).split(".")[0], DBMS.PGSQL))

def tamper(payload):
    """
    Replaces all occurances of operator equal ('=') with operator 'LIKE'

    Example:
        * Input: SELECT * FROM users WHERE id=1
        * Output: SELECT * FROM users WHERE id LIKE 1

    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5

    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the equal character ('=')
        * The LIKE operator is SQL standard. Hence, this tamper script
          should work against all (?) databases
    """

    def process(match):
        word = match.group()
        word = "%sLIKE%s" % (" " if word[0]!=" " else "", " " if word[-1]!=" " else "")

        return word

    retVal = payload

    if payload:
        retVal = re.sub(r"\s*=\s*", lambda match: process(match), retVal)

    return retVal
