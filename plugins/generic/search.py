#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import filterPairValues
from lib.core.common import getLimitRange
from lib.core.common import isInferenceAvailable
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import readInput
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import safeStringFormat
from lib.core.common import unArrayizeValue
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
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import CURRENT_DB
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import UPPER_CASE_DBMSES
from lib.request import inject
from lib.utils.brute import columnExists
from lib.utils.brute import tableExists
from thirdparty import six

class Search(object):
    """
    This class defines search functionalities for plugins.
    """

    def __init__(self):
        pass

    def searchDb(self):
        foundDbs = []
        rootQuery = queries[Backend.getIdentifiedDbms()].search_db
        dbList = conf.db.split(',')

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            dbCond = rootQuery.inband.condition2
        else:
            dbCond = rootQuery.inband.condition

        dbConsider, dbCondParam = self.likeOrExact("database")

        for db in dbList:
            values = []
            db = safeSQLIdentificatorNaming(db)

            if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
                db = db.upper()

            infoMsg = "searching database"
            if dbConsider == "1":
                infoMsg += "s LIKE"
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

            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
                if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                    query = rootQuery.inband.query2
                else:
                    query = rootQuery.inband.query

                query = query % (dbQuery + exclDbsQuery)
                values = inject.getValue(query, blind=False, time=False)

                if not isNoneValue(values):
                    values = arrayizeValue(values)

                    for value in values:
                        value = safeSQLIdentificatorNaming(value)
                        foundDbs.append(value)

            if not values and isInferenceAvailable() and not conf.direct:
                infoMsg = "fetching number of database"
                if dbConsider == "1":
                    infoMsg += "s LIKE"
                infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(db)
                logger.info(infoMsg)

                if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                    query = rootQuery.blind.count2
                else:
                    query = rootQuery.blind.count

                query = query % (dbQuery + exclDbsQuery)
                count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                if not isNumPosStrValue(count):
                    warnMsg = "no database"
                    if dbConsider == "1":
                        warnMsg += "s LIKE"
                    warnMsg += " '%s' found" % unsafeSQLIdentificatorNaming(db)
                    logger.warning(warnMsg)

                    continue

                indexRange = getLimitRange(count)

                for index in indexRange:
                    if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2
                    else:
                        query = rootQuery.blind.query

                    query = query % (dbQuery + exclDbsQuery)
                    query = agent.limitQuery(index, query, dbCond)

                    value = unArrayizeValue(inject.getValue(query, union=False, error=False))
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
            message = "do you want to use common table existence check? %s" % ("[Y/n/q]" if Backend.getIdentifiedDbms() in (DBMS.ACCESS, DBMS.MCKOI, DBMS.EXTREMEDB) else "[y/N/q]")
            choice = readInput(message, default='Y' if 'Y' in message else 'N').upper()

            if choice == 'N':
                return
            elif choice == 'Q':
                raise SqlmapUserQuitException
            else:
                regex = '|'.join(conf.tbl.split(','))
                return tableExists(paths.COMMON_TABLES, regex)

        foundTbls = {}
        tblList = conf.tbl.split(',')
        rootQuery = queries[Backend.getIdentifiedDbms()].search_table
        tblCond = rootQuery.inband.condition
        dbCond = rootQuery.inband.condition2
        tblConsider, tblCondParam = self.likeOrExact("table")

        for tbl in tblList:
            values = []
            tbl = safeSQLIdentificatorNaming(tbl, True)

            if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
                tbl = tbl.upper()
                conf.db = conf.db.upper() if conf.db else conf.db

            infoMsg = "searching table"
            if tblConsider == '1':
                infoMsg += "s LIKE"
            infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(tbl)

            if conf.db == CURRENT_DB:
                conf.db = self.getCurrentDb()

            if dbCond and conf.db:
                _ = conf.db.split(',')
                whereDbsQuery = " AND (" + " OR ".join("%s = '%s'" % (dbCond, unsafeSQLIdentificatorNaming(db)) for db in _) + ")"
                infoMsg += " for database%s '%s'" % ("s" if len(_) > 1 else "", ", ".join(db for db in _))
            elif conf.excludeSysDbs:
                whereDbsQuery = "".join(" AND '%s' != %s" % (unsafeSQLIdentificatorNaming(db), dbCond) for db in self.excludeDbsList)
                msg = "skipping system database%s '%s'" % ("s" if len(self.excludeDbsList) > 1 else "", ", ".join(db for db in self.excludeDbsList))
                logger.info(msg)
            else:
                whereDbsQuery = ""

            if dbCond and conf.exclude:
                whereDbsQuery += " AND %s NOT LIKE '%s'" % (dbCond, re.sub(r"\.[*+]", '%', conf.exclude._original))

            logger.info(infoMsg)

            tblQuery = "%s%s" % (tblCond, tblCondParam)
            tblQuery = tblQuery % unsafeSQLIdentificatorNaming(tbl)

            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
                query = rootQuery.inband.query

                query = query % (tblQuery + whereDbsQuery)
                values = inject.getValue(query, blind=False, time=False)

                if values and Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.FIREBIRD):
                    newValues = []

                    if isinstance(values, six.string_types):
                        values = [values]
                    for value in values:
                        dbName = "SQLite" if Backend.isDbms(DBMS.SQLITE) else "Firebird"
                        newValues.append(["%s%s" % (dbName, METADB_SUFFIX), value])

                    values = newValues

                for foundDb, foundTbl in filterPairValues(values):
                    foundDb = safeSQLIdentificatorNaming(foundDb)
                    foundTbl = safeSQLIdentificatorNaming(foundTbl, True)

                    if foundDb is None or foundTbl is None:
                        continue

                    if foundDb in foundTbls:
                        foundTbls[foundDb].append(foundTbl)
                    else:
                        foundTbls[foundDb] = [foundTbl]

            if not values and isInferenceAvailable() and not conf.direct:
                if Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.FIREBIRD):
                    if len(whereDbsQuery) == 0:
                        infoMsg = "fetching number of databases with table"
                        if tblConsider == "1":
                            infoMsg += "s LIKE"
                        infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(tbl)
                        logger.info(infoMsg)

                        query = rootQuery.blind.count
                        query = query % (tblQuery + whereDbsQuery)
                        count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                        if not isNumPosStrValue(count):
                            warnMsg = "no databases have table"
                            if tblConsider == "1":
                                warnMsg += "s LIKE"
                            warnMsg += " '%s'" % unsafeSQLIdentificatorNaming(tbl)
                            logger.warning(warnMsg)

                            continue

                        indexRange = getLimitRange(count)

                        for index in indexRange:
                            query = rootQuery.blind.query
                            query = query % (tblQuery + whereDbsQuery)
                            query = agent.limitQuery(index, query)

                            foundDb = unArrayizeValue(inject.getValue(query, union=False, error=False))
                            foundDb = safeSQLIdentificatorNaming(foundDb)

                            if foundDb not in foundTbls:
                                foundTbls[foundDb] = []

                            if tblConsider == "2":
                                foundTbls[foundDb].append(tbl)

                        if tblConsider == "2":
                            continue
                    else:
                        for db in conf.db.split(',') if conf.db else (self.getCurrentDb(),):
                            db = safeSQLIdentificatorNaming(db)
                            if db not in foundTbls:
                                foundTbls[db] = []
                else:
                    dbName = "SQLite" if Backend.isDbms(DBMS.SQLITE) else "Firebird"
                    foundTbls["%s%s" % (dbName, METADB_SUFFIX)] = []

                for db in foundTbls:
                    db = safeSQLIdentificatorNaming(db)

                    infoMsg = "fetching number of table"
                    if tblConsider == "1":
                        infoMsg += "s LIKE"
                    infoMsg += " '%s' in database '%s'" % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(db))
                    logger.info(infoMsg)

                    query = rootQuery.blind.count2
                    if Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.FIREBIRD):
                        query = query % unsafeSQLIdentificatorNaming(db)
                    query += " AND %s" % tblQuery

                    count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                    if not isNumPosStrValue(count):
                        warnMsg = "no table"
                        if tblConsider == "1":
                            warnMsg += "s LIKE"
                        warnMsg += " '%s' " % unsafeSQLIdentificatorNaming(tbl)
                        warnMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(db)
                        logger.warning(warnMsg)

                        continue

                    indexRange = getLimitRange(count)

                    for index in indexRange:
                        query = rootQuery.blind.query2

                        if " ORDER BY " in query:
                            query = query.replace(" ORDER BY ", "%s ORDER BY " % (" AND %s" % tblQuery))
                        elif query.endswith("'%s')"):
                            query = query[:-1] + " AND %s)" % tblQuery
                        else:
                            query += " AND %s" % tblQuery

                        if Backend.isDbms(DBMS.FIREBIRD):
                            query = safeStringFormat(query, index)

                        if Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.FIREBIRD):
                            query = safeStringFormat(query, unsafeSQLIdentificatorNaming(db))

                        if not Backend.isDbms(DBMS.FIREBIRD):
                            query = agent.limitQuery(index, query)

                        foundTbl = unArrayizeValue(inject.getValue(query, union=False, error=False))
                        if not isNoneValue(foundTbl):
                            kb.hintValue = foundTbl
                            foundTbl = safeSQLIdentificatorNaming(foundTbl, True)
                            foundTbls[db].append(foundTbl)

        for db in list(foundTbls.keys()):
            if isNoneValue(foundTbls[db]):
                del foundTbls[db]

        if not foundTbls:
            warnMsg = "no databases contain any of the provided tables"
            logger.warning(warnMsg)
            return

        conf.dumper.dbTables(foundTbls)
        self.dumpFoundTables(foundTbls)

    def searchColumn(self):
        bruteForce = False

        self.forceDbmsEnum()

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            errMsg = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            bruteForce = True

        if bruteForce:
            message = "do you want to use common column existence check? %s" % ("[Y/n/q]" if Backend.getIdentifiedDbms() in (DBMS.ACCESS, DBMS.MCKOI, DBMS.EXTREMEDB) else "[y/N/q]")
            choice = readInput(message, default='Y' if 'Y' in message else 'N').upper()

            if choice == 'N':
                return
            elif choice == 'Q':
                raise SqlmapUserQuitException
            else:
                regex = '|'.join(conf.col.split(','))
                conf.dumper.dbTableColumns(columnExists(paths.COMMON_COLUMNS, regex))

                message = "do you want to dump entries? [Y/n] "

                if readInput(message, default='Y', boolean=True):
                    self.dumpAll()

                return

        rootQuery = queries[Backend.getIdentifiedDbms()].search_column
        foundCols = {}
        dbs = {}
        whereDbsQuery = ""
        whereTblsQuery = ""
        infoMsgTbl = ""
        infoMsgDb = ""
        colList = conf.col.split(',')

        if conf.exclude:
            colList = [_ for _ in colList if re.search(conf.exclude, _, re.I) is None]

        origTbl = conf.tbl
        origDb = conf.db
        colCond = rootQuery.inband.condition
        dbCond = rootQuery.inband.condition2
        tblCond = rootQuery.inband.condition3
        colConsider, colCondParam = self.likeOrExact("column")

        for column in colList:
            values = []
            column = safeSQLIdentificatorNaming(column)
            conf.db = origDb
            conf.tbl = origTbl

            if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
                column = column.upper()
                conf.db = conf.db.upper() if conf.db else conf.db
                conf.tbl = conf.tbl.upper() if conf.tbl else conf.tbl

            infoMsg = "searching column"
            if colConsider == "1":
                infoMsg += "s LIKE"
            infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(column)

            foundCols[column] = {}

            if tblCond:
                if conf.tbl:
                    tbls = conf.tbl.split(',')
                    if conf.exclude:
                        tbls = [_ for _ in tbls if re.search(conf.exclude, _, re.I) is None]
                    whereTblsQuery = " AND (" + " OR ".join("%s = '%s'" % (tblCond, unsafeSQLIdentificatorNaming(tbl)) for tbl in tbls) + ")"
                    infoMsgTbl = " for table%s '%s'" % ("s" if len(tbls) > 1 else "", ", ".join(unsafeSQLIdentificatorNaming(tbl) for tbl in tbls))

            if conf.db == CURRENT_DB:
                conf.db = self.getCurrentDb()

            if dbCond:
                if conf.db:
                    _ = conf.db.split(',')
                    whereDbsQuery = " AND (" + " OR ".join("%s = '%s'" % (dbCond, unsafeSQLIdentificatorNaming(db)) for db in _) + ")"
                    infoMsgDb = " in database%s '%s'" % ("s" if len(_) > 1 else "", ", ".join(unsafeSQLIdentificatorNaming(db) for db in _))
                elif conf.excludeSysDbs:
                    whereDbsQuery = "".join(" AND %s != '%s'" % (dbCond, unsafeSQLIdentificatorNaming(db)) for db in self.excludeDbsList)
                    msg = "skipping system database%s '%s'" % ("s" if len(self.excludeDbsList) > 1 else "", ", ".join(unsafeSQLIdentificatorNaming(db) for db in self.excludeDbsList))
                    logger.info(msg)
                else:
                    infoMsgDb = " across all databases"

                if conf.exclude:
                    whereDbsQuery += " AND %s NOT LIKE '%s'" % (dbCond, re.sub(r"\.[*+]", '%', conf.exclude._original))

            logger.info("%s%s%s" % (infoMsg, infoMsgTbl, infoMsgDb))

            colQuery = "%s%s" % (colCond, colCondParam)
            colQuery = colQuery % unsafeSQLIdentificatorNaming(column)

            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
                if not all((conf.db, conf.tbl)):
                    # Enumerate tables containing the column provided if
                    # either of database(s) or table(s) is not provided
                    query = rootQuery.inband.query
                    query = query % (colQuery + whereDbsQuery + whereTblsQuery)
                    values = inject.getValue(query, blind=False, time=False)
                else:
                    # Assume provided databases' tables contain the
                    # column(s) provided
                    values = []

                    for db in conf.db.split(','):
                        for tbl in conf.tbl.split(','):
                            values.append([safeSQLIdentificatorNaming(db), safeSQLIdentificatorNaming(tbl, True)])

                for db, tbl in filterPairValues(values):
                    db = safeSQLIdentificatorNaming(db)
                    tbls = tbl.split(',') if not isNoneValue(tbl) else []

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

            if not values and isInferenceAvailable() and not conf.direct:
                if not conf.db:
                    infoMsg = "fetching number of databases with tables containing column"
                    if colConsider == "1":
                        infoMsg += "s LIKE"
                    infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(column)
                    logger.info("%s%s%s" % (infoMsg, infoMsgTbl, infoMsgDb))

                    query = rootQuery.blind.count
                    query = query % (colQuery + whereDbsQuery + whereTblsQuery)
                    count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                    if not isNumPosStrValue(count):
                        warnMsg = "no databases have tables containing column"
                        if colConsider == "1":
                            warnMsg += "s LIKE"
                        warnMsg += " '%s'" % unsafeSQLIdentificatorNaming(column)
                        logger.warning("%s%s" % (warnMsg, infoMsgTbl))

                        continue

                    indexRange = getLimitRange(count)

                    for index in indexRange:
                        query = rootQuery.blind.query
                        query = query % (colQuery + whereDbsQuery + whereTblsQuery)
                        query = agent.limitQuery(index, query)

                        db = unArrayizeValue(inject.getValue(query, union=False, error=False))
                        db = safeSQLIdentificatorNaming(db)

                        if db not in dbs:
                            dbs[db] = {}

                        if db not in foundCols[column]:
                            foundCols[column][db] = []
                else:
                    for db in conf.db.split(',') if conf.db else (self.getCurrentDb(),):
                        db = safeSQLIdentificatorNaming(db)
                        if db not in foundCols[column]:
                            foundCols[column][db] = []

                origDb = conf.db
                origTbl = conf.tbl

                for column, dbData in foundCols.items():
                    colQuery = "%s%s" % (colCond, colCondParam)
                    colQuery = colQuery % unsafeSQLIdentificatorNaming(column)

                    for db in dbData:
                        conf.db = origDb
                        conf.tbl = origTbl

                        infoMsg = "fetching number of tables containing column"
                        if colConsider == "1":
                            infoMsg += "s LIKE"
                        infoMsg += " '%s' in database '%s'" % (unsafeSQLIdentificatorNaming(column), unsafeSQLIdentificatorNaming(db))
                        logger.info(infoMsg)

                        query = rootQuery.blind.count2
                        if not re.search(r"(?i)%s\Z" % METADB_SUFFIX, db or ""):
                            query = query % unsafeSQLIdentificatorNaming(db)
                            query += " AND %s" % colQuery
                        else:
                            query = query % colQuery

                        query += whereTblsQuery

                        count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                        if not isNumPosStrValue(count):
                            warnMsg = "no tables contain column"
                            if colConsider == "1":
                                warnMsg += "s LIKE"
                            warnMsg += " '%s' " % unsafeSQLIdentificatorNaming(column)
                            warnMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(db)
                            logger.warning(warnMsg)

                            continue

                        indexRange = getLimitRange(count)

                        for index in indexRange:
                            query = rootQuery.blind.query2

                            if re.search(r"(?i)%s\Z" % METADB_SUFFIX, db or ""):
                                query = query % (colQuery + whereTblsQuery)
                            elif query.endswith("'%s')"):
                                query = query[:-1] + " AND %s)" % (colQuery + whereTblsQuery)
                            elif " ORDER BY " in query:
                                query = query.replace(" ORDER BY ", " AND %s ORDER BY " % (colQuery + whereTblsQuery))
                            else:
                                query += " AND %s" % (colQuery + whereTblsQuery)

                            query = safeStringFormat(query, unsafeSQLIdentificatorNaming(db))
                            query = agent.limitQuery(index, query)

                            tbl = unArrayizeValue(inject.getValue(query, union=False, error=False))
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

        if dbs:
            conf.dumper.dbColumns(foundCols, colConsider, dbs)
            self.dumpFoundColumn(dbs, foundCols, colConsider)
        else:
            warnMsg = "no databases have tables containing any of the "
            warnMsg += "provided columns"
            logger.warning(warnMsg)

    def search(self):
        if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
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
            raise SqlmapMissingMandatoryOptionException(errMsg)
