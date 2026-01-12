#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.exception import SqlmapUnsupportedFeatureException
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = "on Snowflake it is not possible to enumerate the user password hashes"
        logger.warning(warnMsg)
        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = "on Snowflake it is not possible to enumerate the user roles"
        logger.warning(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "on Snowflake it is not possible to search databases"
        logger.warning(warnMsg)
        return []

    def searchColumn(self):
        errMsg = "on Snowflake it is not possible to search columns"
        raise SqlmapUnsupportedFeatureException(errMsg)
