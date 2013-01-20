#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii

from lib.core.common import isDBMSVersionAtLeast
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        def escaper(value):
            return "X'%s'" % binascii.hexlify(value)

        retVal = expression

        if isDBMSVersionAtLeast('3'):
            retVal = Syntax._escape(expression, quote, escaper)

        return retVal
