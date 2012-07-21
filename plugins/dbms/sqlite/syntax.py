#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii
import re

from lib.core.common import isDBMSVersionAtLeast
from lib.core.exception import sqlmapSyntaxException
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def unescape(expression, quote=True):
        unescaped = expression

        if isDBMSVersionAtLeast('3'):
            if quote:
                for item in re.findall(r"'[^']+'", expression, re.S):
                    unescaped = unescaped.replace(item, "X'%s'" % binascii.hexlify(item.strip("'")))
            else:
                unescaped = "X'%s'" % binascii.hexlify(expression)

        return unescaped

    @staticmethod
    def escape(expression):
        # Example on SQLite 3, not supported on SQLite 2:
        # select X'48'||X'656c6c6f20576f726c6400'; -- Hello World
        while True:
            index = expression.find("X'")
            if index == -1:
                break

            firstIndex = index
            index = expression[firstIndex+2:].find("'")

            if index == -1:
                raise sqlmapSyntaxException, "Unenclosed ' in '%s'" % expression

            lastIndex = firstIndex + index + 3
            old = expression[firstIndex:lastIndex]
            oldUpper = old.upper()
            oldUpper = oldUpper.replace("X'", "").replace("'", "")

            for i in xrange(len(oldUpper)/2):
                char = oldUpper[i*2:i*2+2]
                escaped = "'%s'" % chr(int(char, 16))
            expression = expression.replace(old, escaped)

        return expression
