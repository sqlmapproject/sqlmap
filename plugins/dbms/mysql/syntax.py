#!/usr/bin/env python2

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import binascii

from lib.core.common import getBytes
from lib.core.common import getUnicode
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    @staticmethod
    def escape(expression, quote=True):
        """
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar")
        'SELECT 0x6162636465666768 FROM foobar'
        """

        def escaper(value):
            return "0x%s" % getUnicode(binascii.hexlify(getBytes(value)))

        return Syntax._escape(expression, quote, escaper)
