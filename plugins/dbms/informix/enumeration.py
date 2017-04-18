#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

    def searchDb(self):
        warnMsg = "on Informix searching of databases is not implemented"
        logger.warn(warnMsg)

        return []

    def searchTable(self):
        warnMsg = "on Informix searching of tables is not implemented"
        logger.warn(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "on Informix searching of columns is not implemented"
        logger.warn(warnMsg)

        return []

    def search(self):
        warnMsg = "on Informix search option is not available"
        logger.warn(warnMsg)
