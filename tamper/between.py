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
    Replaces the greater-than operator (>) with NOT BETWEEN 0 AND # and the equal sign (=) with BETWEEN # AND #

    Tested against:
        * MySQL 8.4.9
        * MariaDB 11.8.8
        * PostgreSQL 16.11
        * SQLite 3.45.1
        * Microsoft SQL Server 2022
        * Oracle 23ai

    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the greater than character
        * The BETWEEN clause is SQL standard, and the rewrite was confirmed
          to run unchanged on every engine listed above

    >>> tamper('1 AND A > B--')
    '1 AND A NOT BETWEEN 0 AND B--'
    >>> tamper('1 AND A = B--')
    '1 AND A BETWEEN B AND B--'
    >>> tamper('1 AND LAST_INSERT_ROWID()=LAST_INSERT_ROWID()')
    '1 AND LAST_INSERT_ROWID() BETWEEN LAST_INSERT_ROWID() AND LAST_INSERT_ROWID()'
    """

    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^>]+?)\s*(?<![<])>(?!=)\s*([^>]+)\s*\Z", payload)  # Note: avoiding compound operators (e.g. >=, <>)

        if match:
            _ = "%s %s NOT BETWEEN 0 AND %s" % (match.group(2), match.group(4), match.group(5))
            retVal = retVal.replace(match.group(0), _)
        else:
            retVal = re.sub(r"\s*(?<![<])>(?!=)\s*(\d+|'[^']+'|\w+\(\d+\))", r" NOT BETWEEN 0 AND \g<1>", payload)

        if retVal == payload:
            match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^=]+?)\s*(?<![<>!])=(?!=)\s*([\w()]+)\s*", payload)  # Note: avoiding compound operators (e.g. >=, !=)

            if match:
                _ = "%s %s BETWEEN %s AND %s" % (match.group(2), match.group(4), match.group(5), match.group(5))
                retVal = retVal.replace(match.group(0), _)

    return retVal
