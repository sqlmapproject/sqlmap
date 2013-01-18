#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import SqlmapSyntaxException
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        if quote:
            while True:
                index = expression.find("'")
                if index == -1:
                    break

                firstIndex = index + 1
                index = expression[firstIndex:].find("'")

                if index == -1:
                    raise SqlmapSyntaxException("Unenclosed ' in '%s'" % expression)

                lastIndex = firstIndex + index
                old = "'%s'" % expression[firstIndex:lastIndex]
                unescaped = "+".join("%s(%d)" % ("CHAR" if ord(expression[i]) < 256 else "TO_UNICHAR", ord(expression[i])) for i in xrange(firstIndex, lastIndex))

                expression = expression.replace(old, unescaped)
        else:
            expression = "+".join("CHAR(%d)" % ord(c) for c in expression)

        return expression
