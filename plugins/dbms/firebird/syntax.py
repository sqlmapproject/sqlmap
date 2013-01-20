#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import isDBMSVersionAtLeast
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        def escaper(value):
            return "||".join("ASCII_CHAR(%d)" % ord(_) for _ in value)

        retVal = expression

        if isDBMSVersionAtLeast('2.1'):
            retVal = Syntax._escape(expression, quote, escaper)

        return retVal
