#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import Backend
from lib.core.datatype import advancedDict

class Unescaper(advancedDict):
    def unescape(self, expression, quote=True, dbms=None):
        identifiedDbms = Backend.getIdentifiedDbms()

        if not expression:
            return expression
        elif "WAITFOR DELAY " in expression:
            return expression
        elif dbms is not None:
            return self[dbms](expression, quote=quote)
        elif identifiedDbms is not None:
            return self[identifiedDbms](expression, quote=quote)
        else:
            return expression

unescaper = Unescaper()
