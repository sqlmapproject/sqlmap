#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.compat import xrange
from lib.core.enums import PRIORITY
from lib.core.settings import REPLACEMENT_MARKER

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def _unwrap(expr):
    """
    Strips only FULLY-wrapping outer parentheses (e.g. '(1=1)' -> '1=1'), leaving a bare function
    call such as 'SLEEP(5)' intact - unlike str.strip('()') which would drop its trailing ')'
    """

    expr = expr.strip()

    while len(expr) > 1 and expr[0] == '(' and expr[-1] == ')':
        depth = 0
        wrapper = True

        for i in xrange(len(expr)):
            if expr[i] == '(':
                depth += 1
            elif expr[i] == ')':
                depth -= 1
                if depth == 0 and i != len(expr) - 1:  # the opening '(' closes before the end
                    wrapper = False
                    break

        if not wrapper:
            break

        expr = expr[1:-1].strip()

    return expr

def tamper(payload, **kwargs):
    """
    Replaces instances like 'IF(A, B, C)' with 'CASE WHEN (A) THEN (B) ELSE (C) END' counterpart

    Requirement:
        * MySQL
        * SQLite (possibly)
        * SAP MaxDB (possibly)

    Tested against:
        * MySQL 5.0 and 5.5

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that filter the IF() functions

    >>> tamper('IF(1, 2, 3)')
    'CASE WHEN (1) THEN (2) ELSE (3) END'
    >>> tamper('SELECT IF((1=1), (SELECT "foo"), NULL)')
    'SELECT CASE WHEN (1=1) THEN (SELECT "foo") ELSE (NULL) END'
    """

    if payload and payload.find("IF(") > -1:
        payload = payload.replace("()", REPLACEMENT_MARKER)
        while payload.find("IF(") > -1:
            index = payload.find("IF(")
            depth = 1
            commas, end = [], None
            quote, doublequote = False, False

            for i in xrange(index + len("IF("), len(payload)):
                if payload[i] == '\'' and (i == 0 or payload[i - 1] != '\\'):
                    quote = not quote
                elif payload[i] == '"' and (i == 0 or payload[i - 1] != '\\'):
                    doublequote = not doublequote

                if not quote and not doublequote:
                    if depth == 1 and payload[i] == ',':
                        commas.append(i)
                    elif depth == 1 and payload[i] == ')':
                        end = i
                        break
                    elif payload[i] == '(':
                        depth += 1
                    elif payload[i] == ')':
                        depth -= 1

            if len(commas) == 2 and end:
                a = _unwrap(payload[index + len("IF("):commas[0]])
                b = _unwrap(payload[commas[0] + 1:commas[1]])
                c = _unwrap(payload[commas[1] + 1:end])
                newVal = "CASE WHEN (%s) THEN (%s) ELSE (%s) END" % (a, b, c)
                payload = payload[:index] + newVal + payload[end + 1:]
            else:
                break

        payload = payload.replace(REPLACEMENT_MARKER, "()")

    return payload
