#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.convert import getBytes
from lib.core.data import conf
from lib.core.enums import DBMS
from lib.core.exception import SqlmapUndefinedMethod

class Syntax(object):
    """
    This class defines generic syntax functionalities for plugins.
    """

    def __init__(self):
        pass

    @staticmethod
    def _escape(expression, quote=True, escaper=None):
        retVal = expression

        if quote:
            # Match a full SQL string literal, honouring the '' (doubled single quote) escape - e.g.
            # 'a''b' is ONE literal whose value is a'b, not 'a'' followed by a dangling b'. The old
            # r"'[^']*'+" split on the inner '' and left the tail bare, corrupting the encoded payload.
            for item in re.findall(r"'(?:[^']|'')*'", expression):
                value = item[1:-1].replace("''", "'")   # inner content with '' collapsed to the real quote
                if value:
                    if Backend.isDbms(DBMS.SQLITE) and "X%s" % item in expression:
                        continue
                    if re.search(r"\[(SLEEPTIME|RAND)", value) is None:  # e.g. '[SLEEPTIME]' marker
                        replacement = escaper(value) if not conf.noEscape else value

                        if replacement != value:
                            retVal = retVal.replace(item, replacement)
                        elif len(value) != len(getBytes(value)) and "n%s" % item not in retVal and Backend.getDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.ORACLE, DBMS.MSSQL):
                            retVal = retVal.replace(item, "n%s" % item)
        else:
            retVal = escaper(expression)

        return retVal

    @staticmethod
    def escape(expression, quote=True):
        errMsg = "'escape' method must be defined "
        errMsg += "inside the specific DBMS plugin"
        raise SqlmapUndefinedMethod(errMsg)
