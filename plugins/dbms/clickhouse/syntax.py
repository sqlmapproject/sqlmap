#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.convert import getOrds
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):
        """
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar") == "SELECT char(97)||char(98)||char(99)||char(100)||char(101)||char(102)||char(103)||char(104) FROM foobar"
        True
        """

        def escaper(value):
            return "||".join("char(%d)" % _ for _ in getOrds(value))

        return Syntax._escape(expression, quote, escaper)
