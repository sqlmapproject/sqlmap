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
        """
        Note: PostgreSQL has a general problem with concenation operator (||) precedence (hence the parentheses enclosing)
              e.g. SELECT 1 WHERE 'a'!='a'||'b' will trigger error ("argument of WHERE must be type boolean, not type text")
        """

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
                unescaped = "(%s)" % "||".join("CHR(%d)" % (ord(expression[i])) for i in xrange(firstIndex, lastIndex))  # Postgres CHR() function already accepts Unicode code point of character(s)

                expression = expression.replace(old, unescaped)
        else:
            expression = "(%s)" % "||".join("CHR(%d)" % ord(c) for c in expression)

        return expression

    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("CHR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find("))")

            if index == -1:
                raise SqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.replace("CHR(", "").replace(")", "")
            oldUpper = oldUpper.split("||")

            escaped = "'%s'" % "".join(chr(int(char)) for char in oldUpper)
            expression = expression.replace(old, escaped)

        return expression
