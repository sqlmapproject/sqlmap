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
        """
        Note: PostgreSQL has a general problem with concenation operator (||) precedence (hence the parentheses enclosing)
              e.g. SELECT 1 WHERE 'a'!='a'||'b' will trigger error ("argument of WHERE must be type boolean, not type text")
        """

        def escaper(value):
            return "(%s)"  % "||".join("CHR(%d)" % ord(_) for _ in value)  # Postgres CHR() function already accepts Unicode code point of character(s)

        return Syntax._escape(expression, quote, escaper)
