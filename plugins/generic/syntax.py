#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.exception import SqlmapUndefinedMethod

class Syntax:
    """
    This class defines generic syntax functionalities for plugins.
    """

    def __init__(self):
        pass

    @staticmethod
    def _escape(expression, quote=True, escaper=None):
        retVal = expression

        if quote:
            for item in re.findall(r"'[^']*'+", expression):
                _ = item[1:-1]
                if _:
                    retVal = retVal.replace(item, escaper(_))
        else:
            retVal = escaper(expression)

        return retVal

    @staticmethod
    def escape(expression, quote=True):
        errMsg = "'escape' method must be defined "
        errMsg += "inside the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)
