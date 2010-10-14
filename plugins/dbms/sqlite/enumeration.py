#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import sqlmapUnsupportedFeatureException

from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self, "SQLite")

    def getCurrentUser(self):
        warnMsg = "on SQLite it is not possible to enumerate the current user"
        logger.warn(warnMsg)

    def getCurrentDb(self):
        warnMsg = "on SQLite it is not possible to enumerate the current database"
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

    def getPrivileges(self):
        warnMsg = "on SQLite it is not possible to enumerate the user privileges"
        logger.warn(warnMsg)

        return {}

    def getDbs(self):
        warnMsg = "on SQLite it is not possible to enumerate databases"
        logger.warn(warnMsg)

        return []

    def dumpAll(self):
        errMsg = "on SQLite you must specify the table and columns to dump"
        raise sqlmapUnsupportedFeatureException, errMsg

    def searchDb(self):
        warnMsg = "on SQLite it is not possible to search databases"
        logger.warn(warnMsg)

        return []

    def searchColumn(self):
        errMsg = "on SQLite you must specify the table and columns to dump"
        raise sqlmapUnsupportedFeatureException, errMsg
