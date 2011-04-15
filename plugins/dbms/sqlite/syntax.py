#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import isDBMSVersionAtLeast
from lib.core.exception import sqlmapSyntaxException

from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def unescape(expression, quote=True):
        if isDBMSVersionAtLeast('3'):
            if quote:
                expression = expression.replace("'", "''")
                while True:
                    index = expression.find("''")
                    if index == -1:
                        break

                    firstIndex = index + 2
                    index = expression[firstIndex:].find("''")

                    if index == -1:
                        raise sqlmapSyntaxException, "Unenclosed ' in '%s'" % expression.replace("''", "'")

                    lastIndex = firstIndex + index
                    old = "''%s''" % expression[firstIndex:lastIndex]
                    unescaped = ""

                    for i in range(firstIndex, lastIndex):
                        unescaped += "X'%x'" % ord(expression[i])
                        if i < lastIndex - 1:
                            unescaped += "||"

                    #unescaped += ")"
                    expression = expression.replace(old, unescaped)
                expression = expression.replace("''", "'")
            else:
                expression = "||".join("X'%x" % ord(c) for c in expression)

        return expression

    @staticmethod
    def escape(expression):
        # Example on SQLite 3, not supported on SQLite 2:
        # select X'48'||X'656c6c6f20576f726c6400'; -- Hello World
        while True:
            index = expression.find("X'")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex+2:].find("'")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ' in '%s'" % expression

            lastIndex = firstIndex + index + 3
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.replace("X'", "").replace("'", "")

            for i in xrange(len(oldUpper)/2):
                char = oldUpper[i*2:i*2+2]
                escaped = "'%s'" % chr(int(char, 16))
            expression = expression.replace(old, escaped)

        return expression
