#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import kb
from lib.core.datatype import advancedDict

class Unescaper(advancedDict):
    def unescape(self, expression, quote=True, dbms=None):
        if hasattr(kb, "dbms") and kb.dbms is not None:
            return self[kb.dbms](expression, quote=quote)
        elif hasattr(kb.misc, "testedDbms") and kb.misc.testedDbms is not None:
            return self[kb.misc.testedDbms](expression, quote=quote)
        elif hasattr(kb.misc, "testedDbms") and kb.misc.testedDbms is not None:
            return self[kb.misc.testedDbms](expression, quote=quote)
        elif dbms is not None:
            return self[dbms](expression, quote=quote)
        else:
            return expression

unescaper = Unescaper()
