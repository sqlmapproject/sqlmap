#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.convert import getOrds
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):
        """
        >>> from lib.core.common import Backend
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar") == "SELECT CHR(97)||CHR(98)||CHR(99)||CHR(100)||CHR(101)||CHR(102)||CHR(103)||CHR(104) FROM foobar"
        True
        """

        def escaper(value):
            return "||".join("CHR(%d)" % _ for _ in getOrds(value))

        return Syntax._escape(expression, quote, escaper)
