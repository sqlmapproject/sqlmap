#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getStatements(self):
        warnMsg = "on Altibase it is not possible to enumerate the SQL statements"
        logger.warning(warnMsg)

        return []

    def getHostname(self):
        warnMsg = "on Altibase it is not possible to enumerate the hostname"
        logger.warning(warnMsg)
