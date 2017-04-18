#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import isDBMSVersionAtLeast
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        """
        >>> from lib.core.common import Backend
        >>> Backend.setVersion('2.0')
        ['2.0']
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar")
        "SELECT 'abcdefgh' FROM foobar"
        >>> Backend.setVersion('2.1')
        ['2.1']
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar")
        'SELECT ASCII_CHAR(97)||ASCII_CHAR(98)||ASCII_CHAR(99)||ASCII_CHAR(100)||ASCII_CHAR(101)||ASCII_CHAR(102)||ASCII_CHAR(103)||ASCII_CHAR(104) FROM foobar'
        """

        def escaper(value):
            return "||".join("ASCII_CHAR(%d)" % ord(_) for _ in value)

        retVal = expression

        if isDBMSVersionAtLeast("2.1"):
            retVal = Syntax._escape(expression, quote, escaper)

        return retVal
