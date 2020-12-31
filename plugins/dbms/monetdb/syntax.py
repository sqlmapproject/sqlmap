#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.convert import getOrds
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):
        """
        >>> from lib.core.common import Backend
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar") == "SELECT CODE(97)||CODE(98)||CODE(99)||CODE(100)||CODE(101)||CODE(102)||CODE(103)||CODE(104) FROM foobar"
        True
        """

        def escaper(value):
            return "||".join("CODE(%d)" % _ for _ in getOrds(value))

        return Syntax._escape(expression, quote, escaper)
