#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii
import re

from lib.core.convert import utf8encode
from lib.core.exception import SqlmapSyntaxException
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        if quote:
            unescaped = expression
            for item in re.findall(r"'[^']+'", expression, re.S):
                try:
                    unescaped = unescaped.replace(item, "0x%s" % binascii.hexlify(item.strip("'")))
                except UnicodeEncodeError:
                    unescaped = unescaped.replace(item, "CONVERT(0x%s USING utf8)" % "".join("%.2x" % ord(_) for _ in utf8encode(item.strip("'"))))
        else:
            unescaped = "0x%s" % binascii.hexlify(expression)

        return unescaped
