#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import isDBMSVersionAtLeast
from lib.core.convert import getOrds
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):
        """
        >>> from lib.core.common import Backend
        >>> Backend.setVersion('2.0')
        ['2.0']
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar") == "SELECT 'abcdefgh' FROM foobar"
        True
        >>> Backend.setVersion('2.1')
        ['2.1']
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar") == "SELECT ASCII_CHAR(97)||ASCII_CHAR(98)||ASCII_CHAR(99)||ASCII_CHAR(100)||ASCII_CHAR(101)||ASCII_CHAR(102)||ASCII_CHAR(103)||ASCII_CHAR(104) FROM foobar"
        True
        """

        def escaper(value):
            return "||".join("ASCII_CHAR(%d)" % _ for _ in getOrds(value))

        retVal = expression

        if isDBMSVersionAtLeast("2.1"):
            retVal = Syntax._escape(expression, quote, escaper)

        return retVal
