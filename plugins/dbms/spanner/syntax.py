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
        Note: Google Standard SQL (Spanner) natively supports converting integer arrays
              to strings via CODE_POINTS_TO_STRING(). This is much cleaner and shorter
              than chaining multiple CHR() functions with the || operator.

        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar") == "SELECT CODE_POINTS_TO_STRING([97, 98, 99, 100, 101, 102, 103, 104]) FROM foobar"
        True
        """

        def escaper(value):
            return "CODE_POINTS_TO_STRING([%s])" % ", ".join(str(_) for _ in getOrds(value))

        return Syntax._escape(expression, quote, escaper)
