#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import getRange
from lib.core.common import isInferenceAvailable
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapNoneDataException
from lib.request import inject

from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

    def getPrivileges(self, *args):
        warnMsg = "on Microsoft SQL Server it is not possible to fetch "
        warnMsg += "database users privileges, sqlmap will check whether "
        warnMsg += "or not the database users are database administrators"
        logger.warn(warnMsg)

        users = []
        areAdmins = set()

        if conf.user:
            users = [ conf.user ]
        elif not len(kb.data.cachedUsers):
            users = self.getUsers()
        else:
            users = kb.data.cachedUsers

        for user in users:
            if user is None:
                continue

            isDba = self.isDba(user)

            if isDba is True:
                areAdmins.add(user)

            kb.data.cachedUsersPrivileges[user] = None

        return ( kb.data.cachedUsersPrivileges, areAdmins )

    def getTables(self):
        if len(kb.data.cachedTables) > 0:
            return kb.data.cachedTables

        self.forceDbmsEnum()

        if conf.db == "CD":
            conf.db = self.getCurrentDb()

        if conf.db:
            dbs = conf.db.split(",")
        else:
            dbs = self.getDbs()

        for db in dbs:
            dbs[dbs.index(db)] = safeSQLIdentificatorNaming(db)

        dbs = filter(None, dbs)

        infoMsg = "fetching tables for database"
        infoMsg += "%s: %s" % ("s" if len(dbs) > 1 else "", ", ".join(db if isinstance(db, basestring) else db[0] for db in sorted(dbs)))
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].tables

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
            for db in dbs:
                db = unArrayizeValue(db)

                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % db
                    logger.info(infoMsg)

                    continue

                for query in (rootQuery.inband.query, rootQuery.inband.query2, rootQuery.inband.query3):
                    query = query.replace("%s", db)
                    value = inject.getValue(query, blind=False)
                    if not isNoneValue(value):
                        break

                if not isNoneValue(value):
                    kb.data.cachedTables[db] = arrayizeValue(value)

        if not kb.data.cachedTables and isInferenceAvailable() and not conf.direct:
            for db in dbs:
                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % db
                    logger.info(infoMsg)

                    continue

                infoMsg = "fetching number of tables for "
                infoMsg += "database '%s'" % db
                logger.info(infoMsg)

                for query in (rootQuery.blind.count, rootQuery.blind.count2, rootQuery.blind.count3):
                    _ = query.replace("%s", db)
                    count = inject.getValue(_, inband=False, error=False, charsetType=2)
                    if not isNoneValue(count):
                        break

                if not isNumPosStrValue(count):
                    if count != "0":
                        warnMsg = "unable to retrieve the number of "
                        warnMsg += "tables for database '%s'" % db
                        logger.warn(warnMsg)
                    continue

                tables = []

                for index in xrange(int(count)):
                    _ = (rootQuery.blind.query if query == rootQuery.blind.count else rootQuery.blind.query2 if query == rootQuery.blind.count2 else rootQuery.blind.query3).replace("%s", db) % index

                    table = inject.getValue(_, inband=False, error=False)
                    kb.hintValue = table
                    table = safeSQLIdentificatorNaming(table, True)
                    tables.append(table)

                if tables:
                    kb.data.cachedTables[db] = tables
                else:
                    warnMsg = "unable to retrieve the tables "
                    warnMsg += "for database '%s'" % db
                    logger.warn(warnMsg)

        if not kb.data.cachedTables:
            errMsg = "unable to retrieve the tables for any database"
            raise sqlmapNoneDataException(errMsg)
        else:
            for db, tables in kb.data.cachedTables.items():
                kb.data.cachedTables[db] = sorted(tables) if tables else tables

        return kb.data.cachedTables

    def searchTable(self):
        rootQuery = queries[Backend.getIdentifiedDbms()].search_table
        foundTbls = {}
        tblList = conf.tbl.split(",")
        tblCond = rootQuery.inband.condition
        dbCond = rootQuery.inband.condition2

        tblConsider, tblCondParam = self.likeOrExact("table")

        if not len(kb.data.cachedDbs):
            enumDbs = self.getDbs()
        else:
            enumDbs = kb.data.cachedDbs

        for db in enumDbs:
            if isinstance(db, list):
                db = db[0]

            db = safeSQLIdentificatorNaming(db)
            foundTbls[db] = []

        for tbl in tblList:
            tbl = safeSQLIdentificatorNaming(tbl, True)

            infoMsg = "searching table"
            if tblConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(tbl)
            logger.info(infoMsg)

            tblQuery = "%s%s" % (tblCond, tblCondParam)
            tblQuery = tblQuery % unsafeSQLIdentificatorNaming(tbl)

            for db in foundTbls.keys():
                db = safeSQLIdentificatorNaming(db)

                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % db
                    logger.info(infoMsg)

                    continue

                if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
                    query = rootQuery.inband.query.replace("%s", db)
                    query += tblQuery
                    values = inject.getValue(query, blind=False)

                    if not isNoneValue(values):
                        if isinstance(values, basestring):
                            values = [ values ]

                        for foundTbl in values:
                            if foundTbl is None:
                                continue

                            foundTbls[db].append(foundTbl)
                else:
                    infoMsg = "fetching number of table"
                    if tblConsider == "1":
                        infoMsg += "s like"
                    infoMsg += " '%s' in database '%s'" % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(db))
                    logger.info(infoMsg)

                    query = rootQuery.blind.count
                    query = query.replace("%s", db)
                    query += " AND %s" % tblQuery
                    count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                    if not isNumPosStrValue(count):
                        warnMsg = "no table"
                        if tblConsider == "1":
                            warnMsg += "s like"
                        warnMsg += " '%s' " % unsafeSQLIdentificatorNaming(tbl)
                        warnMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(db)
                        logger.warn(warnMsg)

                        continue

                    indexRange = getRange(count)

                    for index in indexRange:
                        query = rootQuery.blind.query
                        query = query.replace("%s", db)
                        query += " AND %s" % tblQuery
                        query = agent.limitQuery(index, query, tblCond)
                        tbl = inject.getValue(query, inband=False, error=False)
                        kb.hintValue = tbl
                        foundTbls[db].append(tbl)

        for db, tbls in foundTbls.items():
            if len(tbls) == 0:
                foundTbls.pop(db)

        return foundTbls

    def searchColumn(self):
        rootQuery = queries[Backend.getIdentifiedDbms()].search_column
        foundCols = {}
        dbs = {}
        colList = conf.col.split(",")
        colCond = rootQuery.inband.condition
        colConsider, colCondParam = self.likeOrExact("column")

        if not len(kb.data.cachedDbs):
            enumDbs = self.getDbs()
        else:
            enumDbs = kb.data.cachedDbs

        for db in enumDbs:
            db = safeSQLIdentificatorNaming(db)
            dbs[db] = {}

        for column in colList:
            column = safeSQLIdentificatorNaming(column)

            infoMsg = "searching column"
            if colConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(column)
            logger.info(infoMsg)

            foundCols[column] = {}

            colQuery = "%s%s" % (colCond, colCondParam)
            colQuery = colQuery % unsafeSQLIdentificatorNaming(column)

            for db in dbs.keys():
                db = safeSQLIdentificatorNaming(db)

                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % db
                    logger.info(infoMsg)

                    continue

                if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
                    query = rootQuery.inband.query % (db, db, db, db, db, db)
                    query += " AND %s" % colQuery.replace("[DB]", db)
                    values = inject.getValue(query, blind=False)

                    if not isNoneValue(values):
                        if isinstance(values, basestring):
                            values = [ values ]

                        for foundTbl in values:
                            foundTbl = safeSQLIdentificatorNaming(foundTbl, True)

                            if foundTbl is None:
                                continue

                            if foundTbl not in dbs[db]:
                                dbs[db][foundTbl] = {}

                            if colConsider == "1":
                                conf.db = db
                                conf.tbl = foundTbl
                                conf.col = column

                                self.getColumns(onlyColNames=True)

                                if db in kb.data.cachedColumns and foundTbl in kb.data.cachedColumns[db]\
                                  and not isNoneValue(kb.data.cachedColumns[db][foundTbl]):
                                    dbs[db][foundTbl].update(kb.data.cachedColumns[db][foundTbl])
                                kb.data.cachedColumns = {}
                            else:
                                dbs[db][foundTbl][column] = None

                            if db in foundCols[column]:
                                foundCols[column][db].append(foundTbl)
                            else:
                                foundCols[column][db] = [ foundTbl ]
                else:
                    foundCols[column][db] = []

                    infoMsg = "fetching number of tables containing column"
                    if colConsider == "1":
                        infoMsg += "s like"
                    infoMsg += " '%s' in database '%s'" % (column, db)
                    logger.info(infoMsg)

                    query = rootQuery.blind.count
                    query = query % (db, db, db, db, db, db)
                    query += " AND %s" % colQuery.replace("[DB]", db)
                    count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                    if not isNumPosStrValue(count):
                        warnMsg = "no tables contain column"
                        if colConsider == "1":
                            warnMsg += "s like"
                        warnMsg += " '%s' " % column
                        warnMsg += "in database '%s'" % db
                        logger.warn(warnMsg)

                        continue

                    indexRange = getRange(count)

                    for index in indexRange:
                        query = rootQuery.blind.query
                        query = query % (db, db, db, db, db, db)
                        query += " AND %s" % colQuery.replace("[DB]", db)
                        query = agent.limitQuery(index, query, colCond.replace("[DB]", db))
                        tbl = inject.getValue(query, inband=False, error=False)
                        kb.hintValue = tbl

                        tbl = safeSQLIdentificatorNaming(tbl, True)

                        if tbl not in dbs[db]:
                            dbs[db][tbl] = {}

                        if colConsider == "1":
                            conf.db = db
                            conf.tbl = tbl
                            conf.col = column

                            self.getColumns(onlyColNames=True)

                            if db in kb.data.cachedColumns and tbl in kb.data.cachedColumns[db]:
                                dbs[db][tbl].update(kb.data.cachedColumns[db][tbl])
                            kb.data.cachedColumns = {}
                        else:
                            dbs[db][tbl][column] = None

                        foundCols[column][db].append(tbl)

        self.dumpFoundColumn(dbs, foundCols, colConsider)
