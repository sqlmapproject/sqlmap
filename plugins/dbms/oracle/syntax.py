#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        def escaper(value):
            return "||".join("%s(%d)" % ("CHR" if ord(value[i]) < 256 else "NCHR", ord(value[i])) for i in xrange(len(value)))

        return Syntax._escape(expression, quote, escaper)
