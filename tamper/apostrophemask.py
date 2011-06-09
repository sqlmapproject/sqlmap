#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import string

from lib.core.enums import PRIORITY
from lib.core.exception import sqlmapUnsupportedFeatureException

__priority__ = PRIORITY.LOWEST

def tamper(payload):
    """
    Replaces apostrophe character with it's UTF8 fullwidth counterpart
    Example: "AND '1'='1'" becomes "AND %EF%BC%871%EF%BC%87=%EF%BC%871%EF%BC%87"
    Reference: http://www.utf8-chartable.de/unicode-utf8-table.pl?start=65280&number=128
    """

    retVal = payload

    if payload:
        retVal = payload.replace('\'', '%EF%BC%87')

    return retVal
