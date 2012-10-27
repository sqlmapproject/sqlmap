#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import filterPairValues
from lib.core.common import getLimitRange
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import readInput
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapUserQuitException
from lib.core.settings import CURRENT_DB
from lib.request import inject
from lib.techniques.brute.use import columnExists
from lib.techniques.brute.use import tableExists

class Search:
    """
    This class defines search functionalities for plugins.
    """

    def __init__(self):
        pass

    def searchDb(self):
        foundDbs = []
        rootQuery = queries[Backend.getIdentifiedDbms()].search_db
        dbList = conf.db.split(",")

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            dbCond = rootQuery.inband.condition2
        else:
            dbCond = rootQuery.inband.condition

        dbConsider, dbCondParam = self.likeOrExact("database")

        for db in dbList:
            db = safeSQLIdentificatorNaming(db)

            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                db = db.upper()

            infoMsg = "searching database"
            if dbConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(db)
            logger.info(infoMsg)

            if conf.excludeSysDbs:
                exclDbsQuery = "".join(" AND '%s' != %s" % (unsafeSQLIdentificatorNaming(db), dbCond) for db in self.excludeDbsList)
                infoMsg = "skipping system database%s '%s'" % ("s" if len(self.excludeDbsList) > 1 else "", ", ".join(db for db in self.excludeDbsList))
                logger.info(infoMsg)
            else:
                exclDbsQuery = ""

            dbQuery = "%s%s" % (dbCond, dbCondParam)
            dbQuery = dbQuery % unsafeSQLIdentificatorNaming(db)

            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
                if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                    query = rootQuery.inband.query2
                else:
                    query = rootQuery.inband.query
                query += dbQuery
                query += exclDbsQuery
                values = inject.getValue(query, blind=False, time=False)

                if not isNoneValue(values):
                    values = arrayizeValue(values)

                    for value in values:
                        value = safeSQLIdentificatorNaming(value)
                        foundDbs.append(value)
            else:
                infoMsg = "fetching number of databases"
                if dbConsider == "1":
                    infoMsg += "s like"
                infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(db)
                logger.info(infoMsg)

                if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                    query = rootQuery.blind.count2
                else:
                    query = rootQuery.blind.count

                query += dbQuery
                query += exclDbsQuery
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                if not isNumPosStrValue(count):
                    warnMsg = "no database"
                    if dbConsider == "1":
                        warnMsg += "s like"
                    warnMsg += " '%s' found" % unsafeSQLIdentificatorNaming(db)
                    logger.warn(warnMsg)

                    continue

                indexRange = getLimitRange(count)

                for index in indexRange:
                    if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2
                    else:
                        query = rootQuery.blind.query
                    query += dbQuery
                    query += exclDbsQuery
                    if Backend.isDbms(DBMS.DB2):
                        query += ") AS foobar"
                    query = agent.limitQuery(index, query, dbCond)

                    value = inject.getValue(query, inband=False, error=False)
                    value = safeSQLIdentificatorNaming(value)
                    foundDbs.append(value)

        conf.dumper.lister("found databases", foundDbs)

    def searchTable(self):
        bruteForce = False

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            errMsg = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            bruteForce = True

        if bruteForce:
            message = "do you want to use common table existence check? %s" % ("[Y/n/q]" if Backend.getIdentifiedDbms() in (DBMS.ACCESS,) else "[y/N/q]")
            test = readInput(message, default="Y" if "Y" in message else "N")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException
            else:
                regex = "|".join(conf.tbl.split(","))
                return tableExists(paths.COMMON_TABLES, regex)

        foundTbls = {}
        tblList = conf.tbl.split(",")
        rootQuery = queries[Backend.getIdentifiedDbms()].search_table
        tblCond = rootQuery.inband.condition
        dbCond = rootQuery.inband.condition2
        whereDbsQuery = ""
        tblConsider, tblCondParam = self.likeOrExact("table")

        for tbl in tblList:
            tbl = safeSQLIdentificatorNaming(tbl, True)

            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                tbl = tbl.upper()

            infoMsg = "searching table"
            if tblConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(tbl)

            if conf.db and conf.db != CURRENT_DB:
                _ = conf.db.split(",")
                whereDbsQuery = " AND (" + " OR ".join("%s = '%s'" % (dbCond, unsafeSQLIdentificatorNaming(db)) for db in _) + ")"
                infoMsg += " for database%s '%s'" % ("s" if len(_) > 1 else "", ", ".join(db for db in _))
            elif conf.excludeSysDbs:
                whereDbsQuery = "".join(" AND '%s' != %s" % (unsafeSQLIdentificatorNaming(db), dbCond) for db in self.excludeDbsList)
                infoMsg2 = "skipping system database%s '%s'" % ("s" if len(self.excludeDbsList) > 1 else "", ", ".join(db for db in self.excludeDbsList))
                logger.info(infoMsg2)

            logger.info(infoMsg)

            tblQuery = "%s%s" % (tblCond, tblCondParam)
            tblQuery = tblQuery % tbl

            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
                query = rootQuery.inband.query
                query += tblQuery
                query += whereDbsQuery
                values = inject.getValue(query, blind=False, time=False)

                for foundDb, foundTbl in filterPairValues(values):
                    foundDb = safeSQLIdentificatorNaming(foundDb)
                    foundTbl = safeSQLIdentificatorNaming(foundTbl, True)

                    if foundDb is None or foundTbl is None:
                        continue

                    if foundDb in foundTbls:
                        foundTbls[foundDb].append(foundTbl)
                    else:
                        foundTbls[foundDb] = [foundTbl]
            else:
                infoMsg = "fetching number of databases with table"
                if tblConsider == "1":
                    infoMsg += "s like"
                infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(tbl)
                logger.info(infoMsg)

                query = rootQuery.blind.count
                query += tblQuery
                query += whereDbsQuery
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                if not isNumPosStrValue(count):
                    warnMsg = "no databases have table"
                    if tblConsider == "1":
                        warnMsg += "s like"
                    warnMsg += " '%s'" % unsafeSQLIdentificatorNaming(tbl)
                    logger.warn(warnMsg)

                    continue

                indexRange = getLimitRange(count)

                for index in indexRange:
                    query = rootQuery.blind.query
                    query += tblQuery
                    query += whereDbsQuery
                    if Backend.isDbms(DBMS.DB2):
                        query += ") AS foobar"
                    query = agent.limitQuery(index, query)

                    foundDb = inject.getValue(query, inband=False, error=False)
                    foundDb = safeSQLIdentificatorNaming(foundDb)

                    if foundDb not in foundTbls:
                        foundTbls[foundDb] = []

                    if tblConsider == "2":
                        foundTbls[foundDb].append(tbl)

                if tblConsider == "2":
                    continue

                for db in foundTbls.keys():
                    db = safeSQLIdentificatorNaming(db)

                    infoMsg = "fetching number of table"
                    if tblConsider == "1":
                        infoMsg += "s like"
                    infoMsg += " '%s' in database '%s'" % (unsafeSQLIdentificatorNaming(tbl), db)
                    logger.info(infoMsg)

                    query = rootQuery.blind.count2
                    query = query % unsafeSQLIdentificatorNaming(db)
                    query += " AND %s" % tblQuery
                    count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                    if not isNumPosStrValue(count):
                        warnMsg = "no table"
                        if tblConsider == "1":
                            warnMsg += "s like"
                        warnMsg += " '%s' " % unsafeSQLIdentificatorNaming(tbl)
                        warnMsg += "in database '%s'" % db
                        logger.warn(warnMsg)

                        continue

                    indexRange = getLimitRange(count)

                    for index in indexRange:
                        query = rootQuery.blind.query2
                        query = query % unsafeSQLIdentificatorNaming(db)
                        query += " AND %s" % tblQuery
                        query = agent.limitQuery(index, query)

                        foundTbl = inject.getValue(query, inband=False, error=False)
                        kb.hintValue = foundTbl
                        foundTbl = safeSQLIdentificatorNaming(foundTbl, True)
                        foundTbls[db].append(foundTbl)

        if not foundTbls:
            warnMsg = "no databases contain any of the provided tables"
            logger.warn(warnMsg)
            return

        conf.dumper.dbTables(foundTbls)
        self.dumpFoundTables(foundTbls)

    def searchColumn(self):
        bruteForce = False

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            errMsg = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            bruteForce = True

        if bruteForce:
            message = "do you want to use common column existence check? %s" % ("[Y/n/q]" if Backend.getIdentifiedDbms() in (DBMS.ACCESS,) else "[y/N/q]")
            test = readInput(message, default="Y" if "Y" in message else "N")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException
            else:
                regex = "|".join(conf.col.split(","))
                conf.dumper.dbTableColumns(columnExists(paths.COMMON_COLUMNS, regex))

                message = "do you want to dump entries? [Y/n] "
                output = readInput(message, default="Y")

                if output and output[0] not in ("n", "N"):
                    self.dumpAll()

                return

        rootQuery = queries[Backend.getIdentifiedDbms()].search_column
        foundCols = {}
        dbs = {}
        whereDbsQuery = ""
        whereTblsQuery = ""
        infoMsgTbl = ""
        infoMsgDb = ""
        colList = conf.col.split(",")
        origTbl = conf.tbl
        origDb = conf.db
        colCond = rootQuery.inband.condition
        dbCond = rootQuery.inband.condition2
        tblCond = rootQuery.inband.condition3
        colConsider, colCondParam = self.likeOrExact("column")

        for column in colList:
            column = safeSQLIdentificatorNaming(column)
            conf.db = origDb
            conf.tbl = origTbl

            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                column = column.upper()

            infoMsg = "searching column"
            if colConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(column)

            foundCols[column] = {}

            if conf.tbl:
                _ = conf.tbl.split(",")
                whereTblsQuery = " AND (" + " OR ".join("%s = '%s'" % (tblCond, unsafeSQLIdentificatorNaming(tbl)) for tbl in _) + ")"
                infoMsgTbl = " for table%s '%s'" % ("s" if len(_) > 1 else "", ", ".join(tbl for tbl in _))

            if conf.db and conf.db != CURRENT_DB:
                _ = conf.db.split(",")
                whereDbsQuery = " AND (" + " OR ".join("%s = '%s'" % (dbCond, unsafeSQLIdentificatorNaming(db)) for db in _) + ")"
                infoMsgDb = " in database%s '%s'" % ("s" if len(_) > 1 else "", ", ".join(db for db in _))
            elif conf.excludeSysDbs:
                whereDbsQuery = "".join(" AND %s != '%s'" % (dbCond, unsafeSQLIdentificatorNaming(db)) for db in self.excludeDbsList)
                infoMsg2 = "skipping system database%s '%s'" % ("s" if len(self.excludeDbsList) > 1 else "", ", ".join(db for db in self.excludeDbsList))
                logger.info(infoMsg2)
            else:
                infoMsgDb = " across all databases"

            logger.info("%s%s%s" % (infoMsg, infoMsgTbl, infoMsgDb))

            colQuery = "%s%s" % (colCond, colCondParam)
            colQuery = colQuery % unsafeSQLIdentificatorNaming(column)

            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
                if not all((conf.db, conf.tbl)):
                    # Enumerate tables containing the column provided if
                    # either of database(s) or table(s) is not provided
                    query = rootQuery.inband.query
                    query += colQuery
                    query += whereDbsQuery
                    query += whereTblsQuery
                    values = inject.getValue(query, blind=False, time=False)
                else:
                    # Assume provided databases' tables contain the
                    # column(s) provided
                    values = []

                    for db in conf.db.split(","):
                        for tbl in conf.tbl.split(","):
                            values.append([db, tbl])

                for db, tbl in filterPairValues(values):
                    db = safeSQLIdentificatorNaming(db)
                    tbls = tbl.split(",")

                    for tbl in tbls:
                        tbl = safeSQLIdentificatorNaming(tbl, True)

                        if db is None or tbl is None:
                            continue

                        conf.db = db
                        conf.tbl = tbl
                        conf.col = column

                        self.getColumns(onlyColNames=True, colTuple=(colConsider, colCondParam), bruteForce=False)

                        if db in kb.data.cachedColumns and tbl in kb.data.cachedColumns[db]:
                            if db not in dbs:
                                dbs[db] = {}

                            if tbl not in dbs[db]:
                                dbs[db][tbl] = {}

                            dbs[db][tbl].update(kb.data.cachedColumns[db][tbl])

                            if db in foundCols[column]:
                                foundCols[column][db].append(tbl)
                            else:
                                foundCols[column][db] = [tbl]

                        kb.data.cachedColumns = {}
            else:
                if not conf.db:
                    infoMsg = "fetching number of databases with tables containing column"
                    if colConsider == "1":
                        infoMsg += "s like"
                    infoMsg += " '%s'" % column
                    logger.info("%s%s%s" % (infoMsg, infoMsgTbl, infoMsgDb))

                    query = rootQuery.blind.count
                    query += colQuery
                    query += whereDbsQuery
                    query += whereTblsQuery
                    count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                    if not isNumPosStrValue(count):
                        warnMsg = "no databases have tables containing column"
                        if colConsider == "1":
                            warnMsg += "s like"
                        warnMsg += " '%s'" % column
                        logger.warn("%s%s" % (warnMsg, infoMsgTbl))

                        continue

                    indexRange = getLimitRange(count)

                    for index in indexRange:
                        query = rootQuery.blind.query
                        query += colQuery
                        query += whereDbsQuery
                        query += whereTblsQuery
                        if Backend.isDbms(DBMS.DB2):
                            query += ") AS foobar"
                        query = agent.limitQuery(index, query)
                        db = inject.getValue(query, inband=False, error=False)
                        db = safeSQLIdentificatorNaming(db)

                        if db not in dbs:
                            dbs[db] = {}

                        if db not in foundCols[column]:
                            foundCols[column][db] = []
                else:
                    for db in conf.db.split(","):
                        if db not in foundCols[column]:
                            foundCols[column][db] = []

                origDb = conf.db
                origTbl = conf.tbl

                for column, dbData in foundCols.items():
                    colQuery = "%s%s" % (colCond, colCondParam)
                    colQuery = colQuery % column

                    for db in dbData:
                        db = safeSQLIdentificatorNaming(db)
                        conf.db = origDb
                        conf.tbl = origTbl

                        infoMsg = "fetching number of tables containing column"
                        if colConsider == "1":
                            infoMsg += "s like"
                        infoMsg += " '%s' in database '%s'" % (unsafeSQLIdentificatorNaming(column), db)
                        logger.info(infoMsg)

                        query = rootQuery.blind.count2
                        query = query % db
                        query += " AND %s" % colQuery
                        query += whereTblsQuery
                        count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                        if not isNumPosStrValue(count):
                            warnMsg = "no tables contain column"
                            if colConsider == "1":
                                warnMsg += "s like"
                            warnMsg += " '%s' " % column
                            warnMsg += "in database '%s'" % db
                            logger.warn(warnMsg)

                            continue

                        indexRange = getLimitRange(count)

                        for index in indexRange:
                            query = rootQuery.blind.query2
                            query = query % db
                            query += " AND %s" % colQuery
                            query += whereTblsQuery
                            query = agent.limitQuery(index, query)
                            tbl = inject.getValue(query, inband=False, error=False)
                            kb.hintValue = tbl

                            tbl = safeSQLIdentificatorNaming(tbl, True)

                            conf.db = db
                            conf.tbl = tbl
                            conf.col = column

                            self.getColumns(onlyColNames=True, colTuple=(colConsider, colCondParam), bruteForce=False)

                            if db in kb.data.cachedColumns and tbl in kb.data.cachedColumns[db]:
                                if db not in dbs:
                                    dbs[db] = {}

                                if tbl not in dbs[db]:
                                    dbs[db][tbl] = {}

                                dbs[db][tbl].update(kb.data.cachedColumns[db][tbl])

                            kb.data.cachedColumns = {}

                            if db in foundCols[column]:
                                foundCols[column][db].append(tbl)
                            else:
                                foundCols[column][db] = [tbl]

        if not foundCols:
            warnMsg = "no databases have tables containing any of the "
            warnMsg += "provided columns"
            logger.warn(warnMsg)
            return

        conf.dumper.dbColumns(foundCols, colConsider, dbs)
        self.dumpFoundColumn(dbs, foundCols, colConsider)

    def search(self):
        if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
            for item in ('db', 'tbl', 'col'):
                if getattr(conf, item, None):
                    setattr(conf, item, getattr(conf, item).upper())

        if conf.col:
            self.searchColumn()
        elif conf.tbl:
            self.searchTable()
        elif conf.db:
            self.searchDb()
        else:
            errMsg = "missing parameter, provide -D, -T or -C along "
            errMsg += "with --search"
            raise sqlmapMissingMandatoryOptionException, errMsg
