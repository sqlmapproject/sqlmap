#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        warnMsg = "on eXtremeDB it is not possible to get the banner"
        logger.warning(warnMsg)

        return None

    def getCurrentUser(self):
        warnMsg = "on eXtremeDB it is not possible to enumerate the current user"
        logger.warning(warnMsg)

    def getCurrentDb(self):
        warnMsg = "on eXtremeDB it is not possible to get name of the current database"
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = "on eXtremeDB it is not possible to test if current user is DBA"
        logger.warning(warnMsg)

    def getUsers(self):
        warnMsg = "on eXtremeDB it is not possible to enumerate the users"
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on eXtremeDB it is not possible to enumerate the user password hashes"
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "on eXtremeDB it is not possible to enumerate the user privileges"
        logger.warning(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "on eXtremeDB it is not possible to enumerate databases (use only '--tables')"
        logger.warning(warnMsg)

        return []

    def searchDb(self):
        warnMsg = "on eXtremeDB it is not possible to search databases"
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = "on eXtremeDB it is not possible to search tables"
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "on eXtremeDB it is not possible to search columns"
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = "on eXtremeDB search option is not available"
        logger.warning(warnMsg)

    def getHostname(self):
        warnMsg = "on eXtremeDB it is not possible to enumerate the hostname"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "on eXtremeDB it is not possible to enumerate the SQL statements"
        logger.warning(warnMsg)

        return []
