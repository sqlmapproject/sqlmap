#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces instances like 'IFNULL(A, B)' with 'CASE WHEN ISNULL(A) THEN (B) ELSE (A) END' counterpart

    Requirement:
        * MySQL
        * MariaDB

    Tested against:
        * MySQL 8.4.9
        * MariaDB 11.8.8

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that filter the IFNULL() functions
        * NOT usable against SQLite, despite it having IFNULL(): the replacement
          needs ISNULL(), which SQLite does not provide

    >>> tamper('IFNULL(1, 2)')
    'CASE WHEN ISNULL(1) THEN (2) ELSE (1) END'
    """

    if payload and payload.find("IFNULL(") > -1:
        while payload.find("IFNULL(") > -1:
            index = payload.find("IFNULL(")
            depth = 1
            comma, end = None, None
            quote, doublequote = False, False

            for i in xrange(index + len("IFNULL("), len(payload)):
                if payload[i] == '\'' and (i == 0 or payload[i - 1] != '\\'):
                    quote = not quote
                elif payload[i] == '"' and (i == 0 or payload[i - 1] != '\\'):
                    doublequote = not doublequote

                if not quote and not doublequote:
                    if depth == 1 and payload[i] == ',':
                        comma = i
                    elif depth == 1 and payload[i] == ')':
                        end = i
                        break
                    elif payload[i] == '(':
                        depth += 1
                    elif payload[i] == ')':
                        depth -= 1

            if comma and end:
                _ = payload[index + len("IFNULL("):comma]
                __ = payload[comma + 1:end].lstrip()
                newVal = "CASE WHEN ISNULL(%s) THEN (%s) ELSE (%s) END" % (_, __, _)
                payload = payload[:index] + newVal + payload[end + 1:]
            else:
                break

    return payload
