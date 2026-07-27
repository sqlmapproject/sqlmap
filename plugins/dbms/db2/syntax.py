#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.convert import getBytes
from lib.core.settings import UNICODE_ENCODING
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):
        """
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar") == "SELECT CHR(97)||CHR(98)||CHR(99)||CHR(100)||CHR(101)||CHR(102)||CHR(103)||CHR(104) FROM foobar"
        True
        """

        def escaper(value):
            # CHR() is byte-based on DB2, so a non-ASCII codepoint needs its UTF-8 bytes to form a single char
            result = []
            for char in value:
                if ord(char) < 128:
                    result.append("CHR(%d)" % ord(char))
                else:
                    result.extend("CHR(%d)" % _ for _ in bytearray(getBytes(char, UNICODE_ENCODING, errors="replace", unsafe=False)))
            return "||".join(result)

        return Syntax._escape(expression, quote, escaper)
