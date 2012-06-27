#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def tamper(payload):
    """
    Replaces space character (' ') with a pound character ('#') followed by
    a new line ('\n')

    Example:
        * Input: 1 AND 9227=9227
        * Output: 1%23%0A9227=9227

    Requirement:
        * MSSQL
        * MySQL

    Notes:
        * Useful to bypass several web application firewalls
    """

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                retVal += "%23%0A"
            elif payload[i] == '#' or payload[i:i+3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal
