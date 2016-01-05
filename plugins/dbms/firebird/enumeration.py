#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

    def getDbs(self):
        warnMsg = "on Firebird it is not possible to enumerate databases (use only '--tables')"
        logger.warn(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on Firebird it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "on Firebird it is not possible to search databases"
        logger.warn(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "on Firebird it is not possible to search columns"
        logger.warn(warnMsg)

        return []

    def getHostname(self):
        warnMsg = "on Firebird it is not possible to enumerate the hostname"
        logger.warn(warnMsg)
