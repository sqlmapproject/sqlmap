#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from plugins.generic.syntax import Syntax as GenericSyntax
from lib.core.convert import getOrds

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):
        """
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar") == "SELECT CHAR(97)+CHAR(98)+CHAR(99)+CHAR(100)+CHAR(101)+CHAR(102)+CHAR(103)+CHAR(104) FROM foobar"
        True
        >>> Syntax.escape(u"SELECT 'abcd\xebfgh' FROM foobar") == "SELECT CHAR(97)+CHAR(98)+CHAR(99)+CHAR(100)+NCHAR(235)+CHAR(102)+CHAR(103)+CHAR(104) FROM foobar"
        True
        """

        def escaper(value):
            return "+".join("%s(%d)" % ("CHAR" if _ < 128 else "NCHAR", _) for _ in getOrds(value))

        return Syntax._escape(expression, quote, escaper)
