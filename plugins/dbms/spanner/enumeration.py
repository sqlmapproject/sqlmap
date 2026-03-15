#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from lib.core.settings import SPANNER_DEFAULT_SCHEMA
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getCurrentDb(self):
        return SPANNER_DEFAULT_SCHEMA

    def getCurrentUser(self):
        warnMsg = "on Spanner it is not possible to enumerate the current user"
        logger.warning(warnMsg)

    def isDba(self, user=None):
        warnMsg = "on Spanner it is not possible to test if current user is DBA"
        logger.warning(warnMsg)

    def getUsers(self):
        warnMsg = "on Spanner it is not possible to enumerate the users"
        logger.warning(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on Spanner it is not possible to enumerate the user password hashes"
        logger.warning(warnMsg)

        return {}

    def getRoles(self, *args, **kwargs):
        warnMsg = "on Spanner it is not possible to enumerate the user roles"
        logger.warning(warnMsg)

        return {}

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "on Spanner it is not possible to enumerate the user privileges"
        logger.warning(warnMsg)

        return {}
