#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        warnMsg = "on FrontBase it is not possible to get the banner"
        logger.warning(warnMsg)

        return None

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "on FrontBase it is not possible to enumerate the user privileges"
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = "on FrontBase it is not possible to enumerate the hostname"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "on FrontBase it is not possible to enumerate the SQL statements"
        logger.warning(warnMsg)

        return []
