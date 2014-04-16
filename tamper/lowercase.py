#!/usr/bin/env python

"""
Andrew Kitis of Asterisk Information Security
@nanomebia
www.asteriskinfosec.com.au
04-2014

modified from the original "randomcase.py" script provided by the sqlmap developers

"""

import re

from lib.core.data import kb
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces each keyword character with lower case value

    Tested against:
        * Microsoft SQL Server 2005

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that has poorly written permissive regular expressions
        * This tamper script should work against all (?) databases
        * Some web applications don't like uppercase characters, so forcing
            everything to lowercase can work.

    >>> tamper('INSERT')
    'insert'
    """

    retVal = payload

    if payload:
        for match in re.finditer(r"[A-Za-z_]+", retVal):
            word = match.group()

            _ = str()

            for i in xrange(len(word)):
                _ += word[i].lower()

            retVal = retVal.replace(word, _)

    return retVal
