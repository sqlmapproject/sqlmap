#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload):
    """
    Replaces instances like 'IFNULL(A, B)' with 'IF(ISNULL(A), B, A)'

    Example:
        * Input: IFNULL(1, 2)
        * Output: IF(ISNULL(1), 2, 1)

    Requirement:
        * MySQL
        * SQLite (possibly)
        * SAP MaxDB (possibly)

    Tested against:
        * MySQL 5.0 and 5.5

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that filter the IFNULL() function
    """

    if payload and payload.find("IFNULL") > -1:
        while payload.find("IFNULL(") > -1:
            index = payload.find("IFNULL(")
            deepness = 1
            comma, end = None, None

            for i in xrange(index + len("IFNULL("), len(payload)):
                if deepness == 1 and payload[i] == ',':
                    comma = i

                elif deepness == 1 and payload[i] == ')':
                    end = i
                    break

                elif payload[i] == '(':
                    deepness += 1

                elif payload[i] == ')':
                    deepness -= 1

            if comma and end:
                A = payload[index + len("IFNULL("):comma]
                B = payload[comma + 1:end]
                newVal = "IF(ISNULL(%s),%s,%s)" % (A, B, A)
                payload = payload[:index] + newVal + payload[end+1:]
            else:
                break

    return payload
