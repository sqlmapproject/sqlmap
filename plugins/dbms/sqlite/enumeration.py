#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

    def getCurrentUser(self):
        warnMsg = "on SQLite it is not possible to enumerate the current user"
        logger.warn(warnMsg)

    def getCurrentDb(self):
        warnMsg = "on SQLite it is not possible to get name of the current database"
        logger.warn(warnMsg)

    def isDba(self):
        warnMsg = "on SQLite the current user has all privileges"
        logger.warn(warnMsg)

    def getUsers(self):
        warnMsg = "on SQLite it is not possible to enumerate the users"
        logger.warn(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on SQLite it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}

    def getPrivileges(self, *args):
        warnMsg = "on SQLite it is not possible to enumerate the user privileges"
        logger.warn(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "on SQLite it is not possible to enumerate databases (use only '--tables')"
        logger.warn(warnMsg)

        return []

    def searchDb(self):
        warnMsg = "on SQLite it is not possible to search databases"
        logger.warn(warnMsg)

        return []

    def searchColumn(self):
        errMsg = "on SQLite it is not possible to search columns"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def getHostname(self):
        warnMsg = "on SQLite it is not possible to enumerate the hostname"
        logger.warn(warnMsg)
