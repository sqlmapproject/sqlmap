#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces instances of <int> UNION with <int>e0UNION

    Requirement:
        * MySQL

    Notes:
        * Reference: https://media.blackhat.com/us-13/US-13-Salgado-SQLi-Optimization-and-Obfuscation-Techniques-Slides.pdf

    >>> tamper('SELECT id FROM testdb.users')
    'SELECT id FROM testdb 9.e.users'
    """

    return re.sub("( FROM \w+)\.(\w+)", r"\g<1> 9.e.\g<2>", payload, re.I) if payload else payload
