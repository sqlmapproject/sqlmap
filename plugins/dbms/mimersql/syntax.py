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
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar") == "SELECT UNICODE_CHAR(97)||UNICODE_CHAR(98)||UNICODE_CHAR(99)||UNICODE_CHAR(100)||UNICODE_CHAR(101)||UNICODE_CHAR(102)||UNICODE_CHAR(103)||UNICODE_CHAR(104) FROM foobar"
        True
        """

        def escaper(value):
            return "||".join("UNICODE_CHAR(%d)" % _ for _ in getOrds(value))

        return Syntax._escape(expression, quote, escaper)
