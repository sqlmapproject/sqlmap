#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii

from lib.core.common import isDBMSVersionAtLeast
from lib.core.settings import UNICODE_ENCODING
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        def escaper(value):
            return "CAST(X'%s' AS TEXT)" % binascii.hexlify(value.encode(UNICODE_ENCODING) if isinstance(value, unicode) else value)

        retVal = expression

        if isDBMSVersionAtLeast('3'):
            retVal = Syntax._escape(expression, quote, escaper)

        return retVal
