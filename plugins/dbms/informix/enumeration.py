#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def searchDb(self):
        warnMsg = "on Informix searching of databases is not implemented"
        logger.warning(warnMsg)

        return []

    def searchTable(self):
        warnMsg = "on Informix searching of tables is not implemented"
        logger.warning(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "on Informix searching of columns is not implemented"
        logger.warning(warnMsg)

        return []

    def search(self):
        warnMsg = "on Informix search option is not available"
        logger.warning(warnMsg)

    def getStatements(self):
        warnMsg = "on Informix it is not possible to enumerate the SQL statements"
        logger.warning(warnMsg)

        return []
