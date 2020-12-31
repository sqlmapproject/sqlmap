#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.data import logger
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getPasswordHashes(self):
        warnMsg = "on MimerSQL it is not possible to enumerate password hashes"
        logger.warn(warnMsg)

        return {}

    def getStatements(self):
        warnMsg = "on MimerSQL it is not possible to enumerate the SQL statements"
        logger.warn(warnMsg)

        return []

    def getRoles(self, *args, **kwargs):
        warnMsg = "on MimerSQL it is not possible to enumerate the user roles"
        logger.warn(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = "on MimerSQL it is not possible to enumerate the hostname"
        logger.warn(warnMsg)
