#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import SqlmapSyntaxException
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
                    raise SqlmapSyntaxException, "Unenclosed ' in '%s'" % expression

                lastIndex = firstIndex + index
                old = "'%s'" % expression[firstIndex:lastIndex]
                unescaped = ""

                for i in xrange(firstIndex, lastIndex):
                    unescaped += "CHR(%d)" % (ord(expression[i]))
                    if i < lastIndex - 1:
                        unescaped += "&"

                expression = expression.replace(old, unescaped)
        else:
            unescaped = "".join("CHR(%d)&" % ord(c) for c in expression)
            if unescaped[-1] == "&":
                unescaped = unescaped[:-1]

            expression = unescaped

        return expression

    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("CHR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find(")")

            if index == -1:
                raise SqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.lstrip("CHR(").rstrip(")")
            oldUpper = oldUpper.split("&")

            escaped = "'%s'" % "".join(chr(int(char)) for char in oldUpper)
            expression = expression.replace(old, escaped).replace("'&'", "")

        return expression
