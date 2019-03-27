#!/usr/bin/env python2

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):
        def escaper(value):
            return "&".join("CHR(%d)" % ord(_) for _ in value)

        return Syntax._escape(expression, quote, escaper)
