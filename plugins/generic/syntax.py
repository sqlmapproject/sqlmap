#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.exception import SqlmapUndefinedMethod

class Syntax:
    """
    This class defines generic syntax functionalities for plugins.
    """

    def __init__(self):
        pass

    @staticmethod
    def escape(expression):
        errMsg = "'escape' method must be defined "
        errMsg += "inside the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)
