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
        "SELECT 'abcdefgh' FROM foobar"
        """

        return expression
