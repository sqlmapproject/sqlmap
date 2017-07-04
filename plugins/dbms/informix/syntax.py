#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import randomStr
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
            return "||".join("CHR(%d)" % ord(_) for _ in value)

        excluded = {}
        for _ in re.findall(r"DBINFO\([^)]+\)", expression):
            excluded[_] = randomStr()
            expression = expression.replace(_, excluded[_])

        retVal = Syntax._escape(expression, quote, escaper)

        for _ in excluded.items():
            retVal = retVal.replace(_[1], _[0])

        return retVal