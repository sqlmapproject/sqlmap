#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        """
        Note: PostgreSQL has a general problem with concenation operator (||) precedence (hence the parentheses enclosing)
              e.g. SELECT 1 WHERE 'a'!='a'||'b' will trigger error ("argument of WHERE must be type boolean, not type text")

        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar")
        'SELECT (CHR(97)||CHR(98)||CHR(99)||CHR(100)||CHR(101)||CHR(102)||CHR(103)||CHR(104)) FROM foobar'
        """

        def escaper(value):
            return "(%s)" % "||".join("CHR(%d)" % ord(_) for _ in value)  # Postgres CHR() function already accepts Unicode code point of character(s)

        return Syntax._escape(expression, quote, escaper)
