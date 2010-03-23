#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

from lib.core.exception import sqlmapSyntaxException

from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def unescape(expression, quote=True):
        # The following is not supported on SQLite 2
        return expression

        if quote:
            expression = expression.replace("'", "''")
            while True:
                index = expression.find("''")
                if index == -1:
                    break

                firstIndex = index + 2
                index = expression[firstIndex:].find("''")

                if index == -1:
                    raise sqlmapSyntaxException, "Unenclosed ' in '%s'" % expression.replace("''", "'")

                lastIndex = firstIndex + index
                old = "''%s''" % expression[firstIndex:lastIndex]
                unescaped = ""

                for i in range(firstIndex, lastIndex):
                    unescaped += "X'%x'" % ord(expression[i])
                    if i < lastIndex - 1:
                        unescaped += "||"

                #unescaped += ")"
                expression = expression.replace(old, unescaped)
            expression = expression.replace("''", "'")
        else:
            expression = "||".join("X'%x" % ord(c) for c in expression)

        return expression

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
