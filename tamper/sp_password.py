#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGH

def tamper(payload, **kwargs):
    """
    Appends 'sp_password' to the end of the payload for automatic obfuscation from DBMS logs

    Requirement:
        * MSSQL

    Notes:
        * Appending sp_password to the end of the query will hide it from T-SQL logs as a security measure
        * Reference: http://websec.ca/kb/sql_injection

    >>> tamper('1 AND 9227=9227-- ')
    '1 AND 9227=9227-- sp_password'
    """

    retVal = ""

    if payload:
        retVal = "%s%ssp_password" % (payload, "-- " if not any(_ if _ in payload else None for _ in ('#', "-- ")) else "")

    return retVal
