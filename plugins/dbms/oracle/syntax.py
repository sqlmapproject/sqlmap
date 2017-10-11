#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        """
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar")
        'SELECT CHR(97)||CHR(98)||CHR(99)||CHR(100)||CHR(101)||CHR(102)||CHR(103)||CHR(104) FROM foobar'
        """

        def escaper(value):
            return "||".join("%s(%d)" % ("CHR" if ord(value[i]) < 256 else "NCHR", ord(value[i])) for i in xrange(len(value)))

        return Syntax._escape(expression, quote, escaper)
