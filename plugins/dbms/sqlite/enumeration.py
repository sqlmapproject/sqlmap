#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getCurrentUser(self):
        warnMsg = "on SQLite it is not possible to enumerate the current user"
        logger.warning(warnMsg)

    def getCurrentDb(self):
        warnMsg = "on SQLite it is not possible to get name of the current database"
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = "on SQLite the current user has all privileges"
        logger.warning(warnMsg)

        return True

    def getUsers(self):
        warnMsg = "on SQLite it is not possible to enumerate the users"
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on SQLite it is not possible to enumerate the user password hashes"
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "on SQLite it is not possible to enumerate the user privileges"
        logger.warning(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "on SQLite it is not possible to enumerate databases (use only '--tables')"
        logger.warning(warnMsg)

        return []

    def searchDb(self):
        warnMsg = "on SQLite it is not possible to search databases"
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        errMsg = "on SQLite it is not possible to search columns"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def getHostname(self):
        warnMsg = "on SQLite it is not possible to enumerate the hostname"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "on SQLite it is not possible to enumerate the SQL statements"
        logger.warning(warnMsg)

        return []
