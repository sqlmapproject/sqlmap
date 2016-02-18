#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii

from lib.core.common import Backend
from lib.core.common import isDBMSVersionAtLeast
from lib.core.settings import UNICODE_ENCODING
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        """
        >>> Backend.setVersion('2')
        ['2']
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar")
        "SELECT 'abcdefgh' FROM foobar"
        >>> Backend.setVersion('3')
        ['3']
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar")
        "SELECT CAST(X'6162636465666768' AS TEXT) FROM foobar"
        """

        def escaper(value):
            # Reference: http://stackoverflow.com/questions/3444335/how-do-i-quote-a-utf-8-string-literal-in-sqlite3
            return "CAST(X'%s' AS TEXT)" % binascii.hexlify(value.encode(UNICODE_ENCODING) if isinstance(value, unicode) else value)

        retVal = expression

        if isDBMSVersionAtLeast('3'):
            retVal = Syntax._escape(expression, quote, escaper)

        return retVal
