#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii
import re

from lib.core.exception import sqlmapSyntaxException
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def unescape(expression, quote=True):
        if quote:
            unescaped = expression
            for item in re.findall(r"'[^']+'", expression, re.S):
                try:
                    unescaped = unescaped.replace(item, "0x%s" % binascii.hexlify(item.strip("'")))
                except UnicodeEncodeError:
                    unescaped = unescaped.replace(item, "CHAR(0x%s USING utf8)" % "".join(("%.2x" % ord(_)) if ord(_) < 256 else ("%.4x" % ord(_)) for _ in item.strip("'")))
        else:
            unescaped = "0x%s" % binascii.hexlify(expression)

        return unescaped

    @staticmethod
    def escape(expression):
        while True:
            index = expression.find("CHAR(")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex:].find(")")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ) in '%s'" % expression

            lastIndex = firstIndex + index + 1
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.lstrip("CHAR(").rstrip(")")
            oldUpper = oldUpper.split(",")

            escaped = "'%s'" % "".join(chr(int(char)) for char in oldUpper)
            expression = expression.replace(old, escaped)

        original = expression
        for item in re.findall(r"0x[0-9a-fA-F]+", original, re.S):
            expression = expression.replace(item, "'%s'" % binascii.unhexlify(item[2:]))

        return expression
