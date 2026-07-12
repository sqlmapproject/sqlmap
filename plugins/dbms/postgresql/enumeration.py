#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import Backend
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import FORK

from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getHostname(self):
        warnMsg = "on PostgreSQL it is not possible to enumerate the hostname"
        logger.warning(warnMsg)

    def getColumns(self, *args, **kwargs):
        if not Backend.isFork(FORK.DUCKDB):
            return GenericEnumeration.getColumns(self, *args, **kwargs)

        # DuckDB (PostgreSQL fork) exposes column metadata through information_schema instead of the
        # pg_catalog tables (pg_attribute yields no rows), so swap those queries in for the generic routine
        columns = queries[DBMS.PGSQL].columns
        backup = (columns.inband.query, columns.inband.condition, columns.blind.query, columns.blind.query2, columns.blind.count, columns.blind.condition)

        columns.inband.query = "SELECT column_name,data_type FROM information_schema.columns WHERE table_name='%s' AND table_schema='%s' ORDER BY column_name"
        columns.blind.query = "SELECT column_name FROM information_schema.columns WHERE table_name='%s' AND table_schema='%s' ORDER BY column_name"
        columns.blind.query2 = "SELECT data_type FROM information_schema.columns WHERE table_name='%s' AND column_name='%s' AND table_schema='%s'"
        columns.blind.count = "SELECT COUNT(column_name) FROM information_schema.columns WHERE table_name='%s' AND table_schema='%s'"
        columns.inband.condition = columns.blind.condition = "column_name"

        try:
            return GenericEnumeration.getColumns(self, *args, **kwargs)
        finally:
            columns.inband.query, columns.inband.condition, columns.blind.query, columns.blind.query2, columns.blind.count, columns.blind.condition = backup

    def getUsers(self):
        if Backend.isFork(FORK.DUCKDB):
            warnMsg = "on DuckDB it is not possible to enumerate the users"
            logger.warning(warnMsg)
            return []

        return GenericEnumeration.getUsers(self)

    def getPasswordHashes(self):
        if Backend.isFork(FORK.DUCKDB):
            warnMsg = "on DuckDB it is not possible to enumerate the user password hashes"
            logger.warning(warnMsg)
            return {}

        return GenericEnumeration.getPasswordHashes(self)

    def getPrivileges(self, query2=False):
        if Backend.isFork(FORK.DUCKDB):
            warnMsg = "on DuckDB it is not possible to enumerate the user privileges"
            logger.warning(warnMsg)
            return {}

        return GenericEnumeration.getPrivileges(self, query2)

    def getRoles(self, query2=False):
        if Backend.isFork(FORK.DUCKDB):
            warnMsg = "on DuckDB it is not possible to enumerate the user roles"
            logger.warning(warnMsg)
            return {}

        return GenericEnumeration.getRoles(self, query2)
