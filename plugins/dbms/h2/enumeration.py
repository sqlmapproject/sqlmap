#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import unArrayizeValue
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.settings import H2_DEFAULT_SCHEMA
from lib.request import inject
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getBanner(self):
        if not conf.getBanner:
            return

        if kb.data.banner is None:
            infoMsg = "fetching banner"
            logger.info(infoMsg)

            query = queries[DBMS.H2].banner.query
            kb.data.banner = unArrayizeValue(inject.getValue(query, safeCharEncode=True))

        return kb.data.banner

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "on H2 it is not possible to enumerate the user privileges"
        logger.warning(warnMsg)

        return {}

    def getHostname(self):
        warnMsg = "on H2 it is not possible to enumerate the hostname"
        logger.warning(warnMsg)

    def getCurrentDb(self):
        return H2_DEFAULT_SCHEMA

    def getPasswordHashes(self):
        warnMsg = "on H2 it is not possible to enumerate password hashes"
        logger.warning(warnMsg)

        return {}

    def getStatements(self):
        warnMsg = "on H2 it is not possible to enumerate the SQL statements"
        logger.warning(warnMsg)

        return []
