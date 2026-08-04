#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.convert import getOrds
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):
        """
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar") == "SELECT CHAR(97)+CHAR(98)+CHAR(99)+CHAR(100)+CHAR(101)+CHAR(102)+CHAR(103)+CHAR(104) FROM foobar"
        True
        >>> Syntax.escape(u"SELECT 'abcd\xebfgh' FROM foobar") == "SELECT CHAR(97)+CHAR(98)+CHAR(99)+CHAR(100)+NCHAR(235)+CHAR(102)+CHAR(103)+CHAR(104) FROM foobar"
        True
        >>> Syntax.escape(u"SELECT '\U0001f600' FROM foobar") == "SELECT NCHAR(55357)+NCHAR(56832) FROM foobar"
        True
        """

        def escaper(value):
            chars = []

            for _ in getOrds(value):
                if _ < 128:
                    chars.append("CHAR(%d)" % _)
                elif _ < 0x10000:
                    chars.append("NCHAR(%d)" % _)
                else:
                    _ -= 0x10000
                    chars.append("NCHAR(%d)+NCHAR(%d)" % (0xd800 + (_ >> 10), 0xdc00 + (_ & 0x3ff)))  # SQL Server's NCHAR() only accepts BMP values without SC collation, so split into a surrogate pair

            return "+".join(chars)

        return Syntax._escape(expression, quote, escaper)
