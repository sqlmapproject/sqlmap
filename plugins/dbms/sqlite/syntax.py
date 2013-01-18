#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii
import re

from lib.core.common import isDBMSVersionAtLeast
from lib.core.exception import SqlmapSyntaxException
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        unescaped = expression

        if isDBMSVersionAtLeast('3'):
            if quote:
                for item in re.findall(r"'[^']+'", expression, re.S):
                    unescaped = unescaped.replace(item, "X'%s'" % binascii.hexlify(item.strip("'")))
            else:
                unescaped = "X'%s'" % binascii.hexlify(expression)

        return unescaped
