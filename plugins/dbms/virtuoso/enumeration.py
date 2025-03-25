#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = "on Virtuoso it is not possible to enumerate the user password hashes"
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "on Virtuoso it is not possible to enumerate the user privileges"
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = "on Virtuoso it is not possible to enumerate the user roles"
        logger.warning(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "on Virtuoso it is not possible to search databases"
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = "on Virtuoso it is not possible to search tables"
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "on Virtuoso it is not possible to search columns"
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = "on Virtuoso search option is not available"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "on Virtuoso it is not possible to enumerate the SQL statements"
        logger.warning(warnMsg)

        return []
