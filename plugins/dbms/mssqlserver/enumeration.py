#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

from lib.core.agent import agent
from lib.core.common import getRange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.exception import sqlmapNoneDataException
from lib.request import inject

from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self, "Microsoft SQL Server")

    def getPrivileges(self):
        warnMsg  = "on Microsoft SQL Server it is not possible to fetch "
        warnMsg += "database users privileges"
        logger.warn(warnMsg)

        return {}

    def getTables(self):
        infoMsg = "fetching tables"
        if conf.db:
            infoMsg += " for database '%s'" % conf.db
        logger.info(infoMsg)

        rootQuery = queries[kb.dbms].tables

        if not conf.db:
            if not len(kb.data.cachedDbs):
                dbs = self.getDbs()
            else:
                dbs = kb.data.cachedDbs
        else:
            if "," in conf.db:
                dbs = conf.db.split(",")
            else:
                dbs = [conf.db]

        if kb.unionPosition or conf.direct:
            for db in dbs:
                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % db
                    logger.info(infoMsg)

                    continue

                query = rootQuery["inband"]["query"] % db
                value = inject.getValue(query, blind=False)

                if value:
                    kb.data.cachedTables[db] = value

        if not kb.data.cachedTables and not conf.direct:
            for db in dbs:
                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % db
                    logger.info(infoMsg)

                    continue

                infoMsg  = "fetching number of tables for "
                infoMsg += "database '%s'" % db
                logger.info(infoMsg)

                query = rootQuery["blind"]["count"] % db
                count = inject.getValue(query, inband=False, charsetType=2)

                if not count.isdigit() or not len(count) or count == "0":
                    warnMsg  = "unable to retrieve the number of "
                    warnMsg += "tables for database '%s'" % db
                    logger.warn(warnMsg)
                    continue

                tables = []

                for index in range(int(count)):
                    query = rootQuery["blind"]["query"] % (db, index, db)
                    table = inject.getValue(query, inband=False)
                    tables.append(table)
                    kb.hintValue = table

                if tables:
                    kb.data.cachedTables[db] = tables
                else:
                    warnMsg  = "unable to retrieve the tables "
                    warnMsg += "for database '%s'" % db
                    logger.warn(warnMsg)

        if not kb.data.cachedTables:
            errMsg = "unable to retrieve the tables for any database"
            raise sqlmapNoneDataException(errMsg)

        return kb.data.cachedTables

    def searchTable(self):
        rootQuery = queries[kb.dbms].searchTable
        foundTbls = {}
        tblList = conf.tbl.split(",")
        tblCond = rootQuery["inband"]["condition"]
        dbCond = rootQuery["inband"]["condition2"]

        tblConsider, tblCondParam = self.likeOrExact("table")

        if not len(kb.data.cachedDbs):
            enumDbs = self.getDbs()
        else:
            enumDbs = kb.data.cachedDbs

        for db in enumDbs:
            foundTbls[db] = []

        for tbl in tblList:
            infoMsg = "searching table"
            if tblConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % tbl
            logger.info(infoMsg)

            if conf.excludeSysDbs:
                exclDbsQuery = "".join(" AND '%s' != %s" % (db, dbCond) for db in self.excludeDbsList)
                infoMsg = "skipping system databases '%s'" % ", ".join(db for db in self.excludeDbsList)
                logger.info(infoMsg)
            else:
                exclDbsQuery = ""

            tblQuery = "%s%s" % (tblCond, tblCondParam)
            tblQuery = tblQuery % tbl

            for db in foundTbls.keys():
                if kb.unionPosition or conf.direct:
                    query = rootQuery["inband"]["query"] % db
                    query += tblQuery
                    query += exclDbsQuery
                    values = inject.getValue(query, blind=False)

                    if values:
                        if isinstance(values, str):
                            values = [ values ]

                        for foundTbl in values:
                            foundTbls[db].append(foundTbl)
                else:
                    infoMsg = "fetching number of table"
                    if tblConsider == "1":
                        infoMsg += "s like"
                    infoMsg += " '%s' in database '%s'" % (tbl, db)
                    logger.info(infoMsg)

                    query = rootQuery["blind"]["count2"]
                    query = query % db
                    query += " AND %s" % tblQuery
                    count = inject.getValue(query, inband=False, expected="int", charsetType=2)

                    if not count.isdigit() or not len(count) or count == "0":
                        warnMsg = "no table"
                        if tblConsider == "1":
                            warnMsg += "s like"
                        warnMsg += " '%s' " % tbl
                        warnMsg += "in database '%s'" % db
                        logger.warn(warnMsg)

                        continue

                    indexRange = getRange(count)

                    for index in indexRange:
                        query = rootQuery["blind"]["query2"]
                        query = query % db
                        query += " AND %s" % tblQuery
                        query = agent.limitQuery(index, query, tblCond)
                        tbl = inject.getValue(query, inband=False)
                        kb.hintValue = tbl
                        foundTbls[db].append(tbl)

        for db, tbls in foundTbls.items():
            if len(tbls) == 0:
                foundTbls.pop(db)

        return foundTbls
