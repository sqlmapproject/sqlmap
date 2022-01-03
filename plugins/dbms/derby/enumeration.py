#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import singleTimeWarnMessage
from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = "on Apache Derby it is not possible to enumerate password hashes"
        logger.warn(warnMsg)

        return {}

    def getStatements(self):
        warnMsg = "on Apache Derby it is not possible to enumerate the SQL statements"
        logger.warn(warnMsg)

        return []

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "on Apache Derby it is not possible to enumerate the user privileges"
        logger.warn(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = "on Apache Derby it is not possible to enumerate the user roles"
        logger.warn(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = "on Apache Derby it is not possible to enumerate the hostname"
        logger.warn(warnMsg)

    def getBanner(self):
        warnMsg = "on Apache Derby it is not possible to enumerate the banner"
        singleTimeWarnMessage(warnMsg)
