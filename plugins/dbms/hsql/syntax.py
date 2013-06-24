#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii

from lib.core.convert import utf8encode
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        """
        TODO: Unsure of a method to escape. Perhaps RAWTOHEX/HEXTORAW functions?
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar")
        'SELECT 'abcdefgh' FROM foobar'
        """

        def escaper(value):
            retVal = None
            try:
                retVal = "'%s'" % value
            except UnicodeEncodeError:
                retVal = "CONVERT(0x%s USING utf8)" % "".join("%.2x" % ord(_) for _ in utf8encode(value))
            return retVal

        return Syntax._escape(expression, quote, escaper)
