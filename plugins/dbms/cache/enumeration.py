#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.settings import CACHE_DEFAULT_SCHEMA
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getCurrentDb(self):
        return CACHE_DEFAULT_SCHEMA

    def getUsers(self):
        warnMsg = "on Cache it is not possible to enumerate the users"
        logger.warn(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on Cache it is not possible to enumerate password hashes"
        logger.warn(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "on Cache it is not possible to enumerate the user privileges"
        logger.warn(warnMsg)

        return {}

    def getStatements(self):
        warnMsg = "on Cache it is not possible to enumerate the SQL statements"
        logger.warn(warnMsg)

        return []

    def getRoles(self, *args, **kwargs):
        warnMsg = "on Cache it is not possible to enumerate the user roles"
        logger.warn(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = "on Cache it is not possible to enumerate the hostname"
        logger.warn(warnMsg)
