#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import zeroDepthSearch
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces plus ('+') character with ODBC function {fn CONCAT()}

    Tested against:
        * Microsoft SQL Server 2008

    Requirements:
        * Microsoft SQL Server 2008+

    Notes:
        * Useful in case ('+') character is filtered
        * https://msdn.microsoft.com/en-us/library/bb630290.aspx

    >>> tamper('SELECT CHAR(113)+CHAR(114)+CHAR(115) FROM DUAL')
    'SELECT {fn CONCAT({fn CONCAT(CHAR(113),CHAR(114))},CHAR(115))} FROM DUAL'

    >>> tamper('SELECT (CHAR(113)+CHAR(114)+CHAR(115)) FROM DUAL')
    'SELECT {fn CONCAT({fn CONCAT(CHAR(113),CHAR(114))},CHAR(115))} FROM DUAL'
    """

    retVal = payload

    if payload:
        while True:
            indexes = zeroDepthSearch(retVal, '+')

            if indexes:
                first, last = 0, 0
                for i in xrange(1, len(indexes)):
                    if ' ' in retVal[indexes[0]:indexes[i]]:
                        break
                    else:
                        last = i

                start = retVal[:indexes[first]].rfind(' ') + 1
                end = (retVal[indexes[last] + 1:].find(' ') + indexes[last] + 1) if ' ' in retVal[indexes[last] + 1:] else len(retVal) - 1

                count = 0
                chars = [char for char in retVal]
                for index in indexes[first:last + 1]:
                    if count == 0:
                        chars[index] = ','
                    else:
                        chars[index] = '\x01'
                    count += 1

                retVal = "%s%s%s)}%s" % (retVal[:start], "{fn CONCAT(" * count, ''.join(chars)[start:end].replace('\x01', ")},"), retVal[end:])
            else:
                match = re.search(r"\((CHAR\(\d+.+CHAR\(\d+\))\)", retVal)
                if match:
                    part = match.group(0)
                    indexes = set(zeroDepthSearch(match.group(1), '+'))
                    if not indexes:
                        break

                    count = 0
                    chars = [char for char in part]
                    for i in xrange(1, len(chars)):
                        if i - 1 in indexes:
                            if count == 0:
                                chars[i] = ','
                            else:
                                chars[i] = '\x01'
                            count += 1

                    replacement = "%s%s}" % (("{fn CONCAT(" * count)[:-1], "".join(chars).replace('\x01', ")},"))
                    retVal = retVal.replace(part, replacement)
                else:
                    break

    return retVal
