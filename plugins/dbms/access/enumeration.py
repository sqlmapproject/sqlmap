#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

    def getDbs(self):
        warnMsg = "on Microsoft Access it is not possible to enumerate databases"
        logger.warn(warnMsg)

        return []

    def getBanner(self):
        warnMsg = "on Microsoft Access it is not possible to get a banner"
        logger.warn(warnMsg)

        return None

    def getCurrentDb(self):
        warnMsg = "on Microsoft Access it is not possible to get name of the current database"
        logger.warn(warnMsg)

    def getPasswordHashes(self):
        warnMsg = "on Microsoft Access it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "on Microsoft Access it is not possible to search databases"
        logger.warn(warnMsg)

        return []

    def getCurrentUser(self):
        warnMsg = "on Microsoft Access it is not possible to enumerate the current user"
        logger.warn(warnMsg)

    def getUsers(self):
        warnMsg = "on Microsoft Access it is not possible to enumerate the users"
        logger.warn(warnMsg)

        return []

    def getPrivileges(self, *args):
        warnMsg = "on Microsoft Access it is not possible to enumerate the user privileges"
        logger.warn(warnMsg)

        return {}
