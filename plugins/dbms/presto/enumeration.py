#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        warnMsg = "on Presto it is not possible to get the banner"
        logger.warning(warnMsg)

        return None

    def getCurrentDb(self):
        warnMsg = "on Presto it is not possible to get name of the current database (schema)"
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = "on Presto it is not possible to test if current user is DBA"
        logger.warning(warnMsg)

    def getUsers(self):
        warnMsg = "on Presto it is not possible to enumerate the users"
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on Presto it is not possible to enumerate the user password hashes"
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "on Presto it is not possible to enumerate the user privileges"
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = "on Presto it is not possible to enumerate the user roles"
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = "on Presto it is not possible to enumerate the hostname"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "on Presto it is not possible to enumerate the SQL statements"
        logger.warning(warnMsg)

        return []
