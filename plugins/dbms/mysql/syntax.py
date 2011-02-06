#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import sqlmapSyntaxException

from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def unescape(expression, quote=True):
        if quote:
            while True:
                index = expression.find("'")
                if index == -1:
                    break

                firstIndex = index + 1
                index = expression[firstIndex:].find("'")

                if index == -1:
                    raise sqlmapSyntaxException, "Unenclosed ' in '%s'" % expression

                lastIndex = firstIndex + index
                old = "'%s'" % expression[firstIndex:lastIndex]
                unescaped = ""

                for i in range(firstIndex, lastIndex):
                    unescaped += "%d" % (ord(expression[i]))
                    if i < lastIndex - 1:
                        unescaped += ","

                expression = expression.replace(old, "CHAR(%s)" % unescaped)
        else:
            unescaped  = "CHAR("
            unescaped += ",".join("%d" % ord(c) for c in expression)
            unescaped += ")"

            expression = unescaped

        return expression

    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("CHAR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find(")")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.lstrip("CHAR(").rstrip(")")
            oldUpper = oldUpper.split(",")

            escaped = "'%s'" % "".join([chr(int(char)) for char in oldUpper])
            expression = expression.replace(old, escaped)

        return expression
