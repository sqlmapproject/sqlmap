#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import isDBMSVersionAtLeast
from lib.core.exception import SqlmapSyntaxException
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        if isDBMSVersionAtLeast('2.1'):
            if expression == u"'''":
                return "ASCII_CHAR(%d)" % (ord("'"))

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
                    unescaped = ""

                    for i in xrange(firstIndex, lastIndex):
                        unescaped += "ASCII_CHAR(%d)" % (ord(expression[i]))
                        if i < lastIndex - 1:
                            unescaped += "||"

                    expression = expression.replace(old, unescaped)
            else:
                unescaped = "".join("ASCII_CHAR(%d)||" % ord(c) for c in expression)
                if unescaped[-1] == "||":
                    unescaped = unescaped[:-1]

                expression = unescaped

        return expression

