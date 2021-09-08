#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.datatype import AttribDict
from lib.core.settings import EXCLUDE_UNESCAPE

class Unescaper(AttribDict):
    def escape(self, expression, quote=True, dbms=None):
        if expression is None:
            return expression

        for exclude in EXCLUDE_UNESCAPE:
            if exclude in expression:
                return expression

        identifiedDbms = Backend.getIdentifiedDbms()

        if dbms is not None:
            retVal = self[dbms](expression, quote=quote)
        elif identifiedDbms is not None and identifiedDbms in self:
            retVal = self[identifiedDbms](expression, quote=quote)
        else:
            retVal = expression

        # e.g. inference comparison for '
        retVal = retVal.replace("'''", "''''")

        return retVal

unescaper = Unescaper()
