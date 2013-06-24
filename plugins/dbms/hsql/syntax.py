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
        def escaper(value):
            retVal = "||".join("CHAR(%d)" % ord(value[i]) for i in xrange(len(value)))
            return retVal
