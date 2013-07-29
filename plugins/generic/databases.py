#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import filterPairValues
from lib.core.common import getLimitRange
from lib.core.common import isInferenceAvailable
from lib.core.common import isListLike
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import parseSqliteTableSchema
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import readInput
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import singleTimeWarnMessage
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.dicts import FIREBIRD_TYPES
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import CURRENT_DB
from lib.request import inject
from lib.techniques.brute.use import columnExists
from lib.techniques.brute.use import tableExists

class Databases:
    """
    This class defines databases' enumeration functionalities for plugins.
    """

    def __init__(self):
        kb.data.currentDb = ""
        kb.data.cachedDbs = []
        kb.data.cachedTables = {}
        kb.data.cachedColumns = {}
        kb.data.cachedCounts = {}
        kb.data.dumpedTable = {}

    def getCurrentDb(self):
        infoMsg = "fetching current database"
        logger.info(infoMsg)

        query = queries[Backend.getIdentifiedDbms()].current_db.query

        if not kb.data.currentDb:
            kb.data.currentDb = unArrayizeValue(inject.getValue(query, safeCharEncode=False))

        if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.PGSQL):
            warnMsg = "on %s you'll need to use " % Backend.getIdentifiedDbms()
            warnMsg += "schema names for enumeration as the counterpart to database "
            warnMsg += "names on other DBMSes"
            singleTimeWarnMessage(warnMsg)

        return kb.data.currentDb

    def getDbs(self):
        if len(kb.data.cachedDbs) > 0:
            return kb.data.cachedDbs

        infoMsg = None

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            warnMsg = "information_schema not available, "
            warnMsg += "back-end DBMS is MySQL < 5. database "
            warnMsg += "names will be fetched from 'mysql' database"
            logger.warn(warnMsg)

        elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.PGSQL):
            warnMsg = "schema names are going to be used on %s " % Backend.getIdentifiedDbms()
            warnMsg += "for enumeration as the counterpart to database "
            warnMsg += "names on other DBMSes"
            logger.warn(warnMsg)

            infoMsg = "fetching database (schema) names"

        else:
            infoMsg = "fetching database names"

        if infoMsg:
            logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].dbs

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query
            values = inject.getValue(query, blind=False, time=False)

            if not isNoneValue(values):
                kb.data.cachedDbs = arrayizeValue(values)

        if not kb.data.cachedDbs and isInferenceAvailable() and not conf.direct:
            infoMsg = "fetching number of databases"
            logger.info(infoMsg)

            if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                query = rootQuery.blind.count2
            else:
                query = rootQuery.blind.count
            count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if not isNumPosStrValue(count):
                errMsg = "unable to retrieve the number of databases"
                logger.error(errMsg)
            else:
                plusOne = Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2)
                indexRange = getLimitRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.isDbms(DBMS.SYBASE):
                        query = rootQuery.blind.query % (kb.data.cachedDbs[-1] if kb.data.cachedDbs else " ")
                    elif Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2 % index
                    else:
                        query = rootQuery.blind.query % index
                    db = unArrayizeValue(inject.getValue(query, union=False, error=False))

                    if db:
                        kb.data.cachedDbs.append(safeSQLIdentificatorNaming(db))

        if not kb.data.cachedDbs and Backend.isDbms(DBMS.MSSQL):
            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
                blinds = (False, True)
            else:
                blinds = (True,)

            for blind in blinds:
                count = 0
                kb.data.cachedDbs = []
                while True:
                    query = rootQuery.inband.query2 % count
                    value = unArrayizeValue(inject.getValue(query, blind=blind))
                    if not (value or "").strip():
                        break
                    else:
                        kb.data.cachedDbs.append(value)
                        count += 1
                if kb.data.cachedDbs:
                    break

        if not kb.data.cachedDbs:
            infoMsg = "falling back to current database"
            logger.info(infoMsg)
            self.getCurrentDb()

            if kb.data.currentDb:
                kb.data.cachedDbs = [kb.data.currentDb]
            else:
                errMsg = "unable to retrieve the database names"
                raise SqlmapNoneDataException(errMsg)
        else:
            kb.data.cachedDbs.sort()

        if kb.data.cachedDbs:
            kb.data.cachedDbs = list(set(kb.data.cachedDbs))

        return kb.data.cachedDbs

    def getTables(self, bruteForce=None):
        if len(kb.data.cachedTables) > 0:
            return kb.data.cachedTables

        self.forceDbmsEnum()

        if bruteForce is None:
            if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                errMsg = "information_schema not available, "
                errMsg += "back-end DBMS is MySQL < 5.0"
                logger.error(errMsg)
                bruteForce = True

            elif Backend.isDbms(DBMS.ACCESS):
                try:
                    tables = self.getTables(False)
                except SqlmapNoneDataException:
                    tables = None

                if not tables:
                    errMsg = "cannot retrieve table names, "
                    errMsg += "back-end DBMS is Access"
                    logger.error(errMsg)
                    bruteForce = True
                else:
                    return tables

        if conf.db == CURRENT_DB:
            conf.db = self.getCurrentDb()

        if conf.db and Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.HSQLDB):
            conf.db = conf.db.upper()

        if conf.db:
            dbs = conf.db.split(",")
        else:
            dbs = self.getDbs()

        for db in dbs:
            dbs[dbs.index(db)] = safeSQLIdentificatorNaming(db)

        dbs = filter(None, dbs)

        if bruteForce:
            resumeAvailable = False

            for db, table in kb.brute.tables:
                if db == conf.db:
                    resumeAvailable = True
                    break

            if resumeAvailable:
                for db, table in kb.brute.tables:
                    if db == conf.db:
                        if conf.db not in kb.data.cachedTables:
                            kb.data.cachedTables[conf.db] = [table]
                        else:
                            kb.data.cachedTables[conf.db].append(table)

                return kb.data.cachedTables

            message = "do you want to use common table existence check? %s" % ("[Y/n/q]" if Backend.getIdentifiedDbms() in (DBMS.ACCESS,) else "[y/N/q]")
            test = readInput(message, default="Y" if "Y" in message else "N")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise SqlmapUserQuitException
            else:
                return tableExists(paths.COMMON_TABLES)

        infoMsg = "fetching tables for database"
        infoMsg += "%s: '%s'" % ("s" if len(dbs) > 1 else "", ", ".join(unsafeSQLIdentificatorNaming(unArrayizeValue(db)) for db in sorted(dbs)))
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].tables

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            query = rootQuery.inband.query
            condition = rootQuery.inband.condition if 'condition' in rootQuery.inband else None

            if condition:
                if not Backend.isDbms(DBMS.SQLITE):
                    query += " WHERE %s" % condition

                    if conf.excludeSysDbs:
                        infoMsg = "skipping system database%s '%s'" % ("s" if len(self.excludeDbsList) > 1 else "", ", ".join(unsafeSQLIdentificatorNaming(db) for db in self.excludeDbsList))
                        logger.info(infoMsg)
                        query += " IN (%s)" % ",".join("'%s'" % unsafeSQLIdentificatorNaming(db) for db in sorted(dbs) if db not in self.excludeDbsList)
                    else:
                        query += " IN (%s)" % ",".join("'%s'" % unsafeSQLIdentificatorNaming(db) for db in sorted(dbs))

                if len(dbs) < 2 and ("%s," % condition) in query:
                    query = query.replace("%s," % condition, "", 1)

            values = inject.getValue(query, blind=False, time=False)

            if not isNoneValue(values):
                values = filter(None, arrayizeValue(values))

                if len(values) > 0 and not isListLike(values[0]):
                    values = [(dbs[0], _) for _ in values]

                for db, table in filterPairValues(values):
                    db = safeSQLIdentificatorNaming(db)
                    table = safeSQLIdentificatorNaming(table, True)

                    if db not in kb.data.cachedTables:
                        kb.data.cachedTables[db] = [table]
                    else:
                        kb.data.cachedTables[db].append(table)

        if not kb.data.cachedTables and isInferenceAvailable() and not conf.direct:
            for db in dbs:
                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % unsafeSQLIdentificatorNaming(db)
                    logger.info(infoMsg)

                    continue

                infoMsg = "fetching number of tables for "
                infoMsg += "database '%s'" % unsafeSQLIdentificatorNaming(db)
                logger.info(infoMsg)

                if Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.FIREBIRD, DBMS.MAXDB, DBMS.ACCESS):
                    query = rootQuery.blind.count
                else:
                    query = rootQuery.blind.count % unsafeSQLIdentificatorNaming(db)

                count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                if count == 0:
                    warnMsg = "database '%s' " % unsafeSQLIdentificatorNaming(db)
                    warnMsg += "appears to be empty"
                    logger.warn(warnMsg)
                    continue

                elif not isNumPosStrValue(count):
                    warnMsg = "unable to retrieve the number of "
                    warnMsg += "tables for database '%s'" % unsafeSQLIdentificatorNaming(db)
                    logger.warn(warnMsg)
                    continue

                tables = []

                plusOne = Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2)
                indexRange = getLimitRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.isDbms(DBMS.SYBASE):
                        query = rootQuery.blind.query % (db, (kb.data.cachedTables[-1] if kb.data.cachedTables else " "))
                    elif Backend.getIdentifiedDbms() in (DBMS.MAXDB, DBMS.ACCESS):
                        query = rootQuery.blind.query % (kb.data.cachedTables[-1] if kb.data.cachedTables else " ")
                    elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.FIREBIRD):
                        query = rootQuery.blind.query % index
                    else:
                        query = rootQuery.blind.query % (unsafeSQLIdentificatorNaming(db), index)

                    table = unArrayizeValue(inject.getValue(query, union=False, error=False))
                    if not isNoneValue(table):
                        kb.hintValue = table
                        table = safeSQLIdentificatorNaming(table, True)
                        tables.append(table)

                if tables:
                    kb.data.cachedTables[db] = tables
                else:
                    warnMsg = "unable to retrieve the table names "
                    warnMsg += "for database '%s'" % unsafeSQLIdentificatorNaming(db)
                    logger.warn(warnMsg)

        if isNoneValue(kb.data.cachedTables):
            kb.data.cachedTables.clear()

        if not kb.data.cachedTables:
            errMsg = "unable to retrieve the table names for any database"
            if bruteForce is None:
                logger.error(errMsg)
                return self.getTables(bruteForce=True)
            else:
                raise SqlmapNoneDataException(errMsg)
        else:
            for db, tables in kb.data.cachedTables.items():
                kb.data.cachedTables[db] = sorted(tables) if tables else tables

        if kb.data.cachedTables:
            for db in kb.data.cachedTables.keys():
                kb.data.cachedTables[db] = list(set(kb.data.cachedTables[db]))

        return kb.data.cachedTables

    def getColumns(self, onlyColNames=False, colTuple=None, bruteForce=None):
        self.forceDbmsEnum()

        if conf.db is None or conf.db == CURRENT_DB:
            if conf.db is None:
                warnMsg = "missing database parameter. sqlmap is going "
                warnMsg += "to use the current database to enumerate "
                warnMsg += "table(s) columns"
                logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

            if not conf.db:
                errMsg = "unable to retrieve the current "
                errMsg += "database name"
                raise SqlmapNoneDataException(errMsg)

        elif conf.db is not None:
            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.HSQLDB):
                conf.db = conf.db.upper()

            if  ',' in conf.db:
                errMsg = "only one database name is allowed when enumerating "
                errMsg += "the tables' columns"
                raise SqlmapMissingMandatoryOptionException(errMsg)

        conf.db = safeSQLIdentificatorNaming(conf.db)

        if conf.col:
            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                conf.col = conf.col.upper()

            colList = conf.col.split(",")
        else:
            colList = []

        for col in colList:
            colList[colList.index(col)] = safeSQLIdentificatorNaming(col)

        colList = filter(None, colList)

        if conf.tbl:
            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                conf.tbl = conf.tbl.upper()

            tblList = conf.tbl.split(",")
        else:
            self.getTables()

            if len(kb.data.cachedTables) > 0:
                if conf.db in kb.data.cachedTables:
                    tblList = kb.data.cachedTables[conf.db]
                else:
                    tblList = kb.data.cachedTables.values()

                if isinstance(tblList[0], (set, tuple, list)):
                    tblList = tblList[0]

                tblList = list(tblList)
            else:
                errMsg = "unable to retrieve the tables "
                errMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                raise SqlmapNoneDataException(errMsg)

        tblList = filter(None, (safeSQLIdentificatorNaming(_, True) for _ in tblList))

        if bruteForce is None:
            if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                errMsg = "information_schema not available, "
                errMsg += "back-end DBMS is MySQL < 5.0"
                logger.error(errMsg)
                bruteForce = True

            elif Backend.isDbms(DBMS.ACCESS):
                errMsg = "cannot retrieve column names, "
                errMsg += "back-end DBMS is Access"
                logger.error(errMsg)
                bruteForce = True

        if bruteForce:
            resumeAvailable = False

            for tbl in tblList:
                for db, table, colName, colType in kb.brute.columns:
                    if db == conf.db and table == tbl:
                        resumeAvailable = True
                        break

            if resumeAvailable or colList:
                columns = {}

                for column in colList:
                    columns[column] = None

                for tbl in tblList:
                    for db, table, colName, colType in kb.brute.columns:
                        if db == conf.db and table == tbl:
                            columns[colName] = colType

                    if conf.db in kb.data.cachedColumns:
                        kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)] = columns
                    else:
                        kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = {safeSQLIdentificatorNaming(tbl, True): columns}

                return kb.data.cachedColumns

            message = "do you want to use common column existence check? %s" % ("[Y/n/q]" if Backend.getIdentifiedDbms() in (DBMS.ACCESS,) else "[y/N/q]")
            test = readInput(message, default="Y" if "Y" in message else "N")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise SqlmapUserQuitException
            else:
                return columnExists(paths.COMMON_COLUMNS)

        rootQuery = queries[Backend.getIdentifiedDbms()].columns
        condition = rootQuery.blind.condition if 'condition' in rootQuery.blind else None

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            for tbl in tblList:
                if conf.db is not None and len(kb.data.cachedColumns) > 0 \
                   and conf.db in kb.data.cachedColumns and tbl in \
                   kb.data.cachedColumns[conf.db]:
                    infoMsg = "fetched tables' columns on "
                    infoMsg += "database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    logger.info(infoMsg)

                    return {conf.db: kb.data.cachedColumns[conf.db]}

                infoMsg = "fetching columns "
                condQuery = ""

                if len(colList) > 0:
                    if colTuple:
                        _, colCondParam = colTuple
                        infoMsg += "like '%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))
                    else:
                        colCondParam = "='%s'"
                        infoMsg += "'%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))

                    condQueryStr = "%%s%s" % colCondParam
                    condQuery = " AND (%s)" % " OR ".join(condQueryStr % (condition, unsafeSQLIdentificatorNaming(col)) for col in sorted(colList))

                infoMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                infoMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                logger.info(infoMsg)

                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.HSQLDB):
                    query = rootQuery.inband.query % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))
                    query += condQuery
                elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                    query = rootQuery.inband.query % (unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(conf.db.upper()))
                    query += condQuery
                elif Backend.isDbms(DBMS.MSSQL):
                    query = rootQuery.inband.query % (conf.db, conf.db, conf.db, conf.db,
                                                      conf.db, conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl).split(".")[-1])
                    query += condQuery.replace("[DB]", conf.db)
                elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.FIREBIRD):
                    query = rootQuery.inband.query % tbl

                values = inject.getValue(query, blind=False, time=False)

                if Backend.isDbms(DBMS.MSSQL) and isNoneValue(values):
                    index, values = 1, []

                    while True:
                        query = rootQuery.inband.query2 % (conf.db, tbl, index)
                        value = unArrayizeValue(inject.getValue(query, blind=False, time=False))

                        if isNoneValue(value) or value == " ":
                            break
                        else:
                            values.append((value,))
                            index += 1

                if Backend.isDbms(DBMS.SQLITE):
                    parseSqliteTableSchema(unArrayizeValue(values))
                elif not isNoneValue(values):
                    table = {}
                    columns = {}

                    for columnData in values:
                        if not isNoneValue(columnData):
                            name = safeSQLIdentificatorNaming(columnData[0])

                            if name:
                                if conf.getComments:
                                    _ = queries[Backend.getIdentifiedDbms()].column_comment
                                    if hasattr(_, "query"):
                                        if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                                            query = _.query % (unsafeSQLIdentificatorNaming(conf.db.upper()), unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(name.upper()))
                                        else:
                                            query = _.query % (unsafeSQLIdentificatorNaming(conf.db), unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(name))
                                        comment = unArrayizeValue(inject.getValue(query, blind=False, time=False))
                                    else:
                                        warnMsg = "on %s it is not " % Backend.getIdentifiedDbms()
                                        warnMsg += "possible to get column comments"
                                        singleTimeWarnMessage(warnMsg)

                                if len(columnData) == 1:
                                    columns[name] = None
                                else:
                                    if Backend.isDbms(DBMS.FIREBIRD):
                                        columnData[1] = FIREBIRD_TYPES.get(columnData[1], columnData[1])

                                    columns[name] = columnData[1]

                    if conf.db in kb.data.cachedColumns:
                        kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)] = columns
                    else:
                        table[safeSQLIdentificatorNaming(tbl, True)] = columns
                        kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = table

        elif isInferenceAvailable() and not conf.direct:
            for tbl in tblList:
                if conf.db is not None and len(kb.data.cachedColumns) > 0 \
                   and conf.db in kb.data.cachedColumns and tbl in \
                   kb.data.cachedColumns[conf.db]:
                    infoMsg = "fetched tables' columns on "
                    infoMsg += "database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    logger.info(infoMsg)

                    return {conf.db: kb.data.cachedColumns[conf.db]}

                infoMsg = "fetching columns "
                condQuery = ""

                if len(colList) > 0:
                    if colTuple:
                        _, colCondParam = colTuple
                        infoMsg += "like '%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))
                    else:
                        colCondParam = "='%s'"
                        infoMsg += "'%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))

                    condQueryStr = "%%s%s" % colCondParam
                    condQuery = " AND (%s)" % " OR ".join(condQueryStr % (condition, unsafeSQLIdentificatorNaming(col)) for col in sorted(colList))

                infoMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                infoMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                logger.info(infoMsg)

                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                    query = rootQuery.blind.count % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))
                    query += condQuery

                elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                    query = rootQuery.blind.count % (unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(conf.db.upper()))
                    query += condQuery

                elif Backend.isDbms(DBMS.MSSQL):
                    query = rootQuery.blind.count % (conf.db, conf.db, \
                        unsafeSQLIdentificatorNaming(tbl).split(".")[-1])
                    query += condQuery.replace("[DB]", conf.db)

                elif Backend.isDbms(DBMS.FIREBIRD):
                    query = rootQuery.blind.count % (tbl)
                    query += condQuery

                elif Backend.isDbms(DBMS.SQLITE):
                    query = rootQuery.blind.query % tbl
                    value = unArrayizeValue(inject.getValue(query, union=False, error=False))
                    parseSqliteTableSchema(value)
                    return kb.data.cachedColumns

                count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                table = {}
                columns = {}

                if not isNumPosStrValue(count):
                    if Backend.isDbms(DBMS.MSSQL):
                        count, index, values = 0, 1, []
                        while True:
                            query = rootQuery.blind.query3 % (conf.db, tbl, index)
                            value = unArrayizeValue(inject.getValue(query, union=False, error=False))
                            if isNoneValue(value) or value == " ":
                                break
                            else:
                                columns[safeSQLIdentificatorNaming(value)] = None
                                index += 1

                    if not columns:
                        errMsg = "unable to retrieve the %scolumns " % ("number of " if not Backend.isDbms(DBMS.MSSQL) else "")
                        errMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                        errMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                        logger.error(errMsg)
                        continue

                for index in getLimitRange(count):
                    if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                        query = rootQuery.blind.query % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))
                        query += condQuery
                        field = None
                    elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                        query = rootQuery.blind.query % (unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(conf.db.upper()))
                        query += condQuery
                        field = None
                    elif Backend.isDbms(DBMS.MSSQL):
                        query = rootQuery.blind.query.replace("'%s'", "'%s'" % unsafeSQLIdentificatorNaming(tbl).split(".")[-1]).replace("%s", conf.db).replace("%d", str(index))
                        query += condQuery.replace("[DB]", conf.db)
                        field = condition.replace("[DB]", conf.db)
                    elif Backend.isDbms(DBMS.FIREBIRD):
                        query = rootQuery.blind.query % (tbl)
                        query += condQuery
                        field = None

                    query = agent.limitQuery(index, query, field, field)
                    column = unArrayizeValue(inject.getValue(query, union=False, error=False))

                    if not isNoneValue(column):
                        if conf.getComments:
                            _ = queries[Backend.getIdentifiedDbms()].column_comment
                            if hasattr(_, "query"):
                                if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                                    query = _.query % (unsafeSQLIdentificatorNaming(conf.db.upper()), unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(column.upper()))
                                else:
                                    query = _.query % (unsafeSQLIdentificatorNaming(conf.db), unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(column))
                                comment = unArrayizeValue(inject.getValue(query, union=False, error=False))
                            else:
                                warnMsg = "on %s it is not " % Backend.getIdentifiedDbms()
                                warnMsg += "possible to get column comments"
                                singleTimeWarnMessage(warnMsg)

                        if not onlyColNames:
                            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                                query = rootQuery.blind.query2 % (unsafeSQLIdentificatorNaming(tbl), column, unsafeSQLIdentificatorNaming(conf.db))
                            elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                                query = rootQuery.blind.query2 % (unsafeSQLIdentificatorNaming(tbl.upper()), column, unsafeSQLIdentificatorNaming(conf.db.upper()))
                            elif Backend.isDbms(DBMS.MSSQL):
                                query = rootQuery.blind.query2 % (conf.db, conf.db, conf.db, conf.db, column, conf.db,
                                                                conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl).split(".")[-1])
                            elif Backend.isDbms(DBMS.FIREBIRD):
                                query = rootQuery.blind.query2 % (tbl, column)

                            colType = unArrayizeValue(inject.getValue(query, union=False, error=False))

                            if Backend.isDbms(DBMS.FIREBIRD):
                                colType = FIREBIRD_TYPES.get(colType, colType)

                            column = safeSQLIdentificatorNaming(column)
                            columns[column] = colType
                        else:
                            column = safeSQLIdentificatorNaming(column)
                            columns[column] = None

                if columns:
                    if conf.db in kb.data.cachedColumns:
                        kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)] = columns
                    else:
                        table[safeSQLIdentificatorNaming(tbl, True)] = columns
                        kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = table

        if not kb.data.cachedColumns:
            warnMsg = "unable to retrieve column names for "
            warnMsg += ("table '%s' " % unsafeSQLIdentificatorNaming(unArrayizeValue(tblList))) if len(tblList) == 1 else "any table "
            warnMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
            logger.warn(warnMsg)

            if bruteForce is None:
                return self.getColumns(onlyColNames=onlyColNames, colTuple=colTuple, bruteForce=True)

        return kb.data.cachedColumns

    def getSchema(self):
        infoMsg = "enumerating database management system schema"
        logger.info(infoMsg)

        pushValue(conf.db)
        pushValue(conf.tbl)
        pushValue(conf.col)

        conf.db = None
        conf.tbl = None
        conf.col = None
        kb.data.cachedTables = {}
        kb.data.cachedColumns = {}

        self.getTables()

        infoMsg = "fetched tables: "
        infoMsg += ", ".join(["%s" % ", ".join("%s%s%s" % (unsafeSQLIdentificatorNaming(db), ".." if \
                   Backend.isDbms(DBMS.MSSQL) or Backend.isDbms(DBMS.SYBASE) \
                   else ".", unsafeSQLIdentificatorNaming(t)) for t in tbl) for db, tbl in \
                   kb.data.cachedTables.items()])
        logger.info(infoMsg)

        for db, tables in kb.data.cachedTables.items():
            for tbl in tables:
                conf.db = db
                conf.tbl = tbl

                self.getColumns()

        conf.col = popValue()
        conf.tbl = popValue()
        conf.db = popValue()

        return kb.data.cachedColumns

    def _tableGetCount(self, db, table):
        if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
            db = db.upper()
            table = table.upper()

        if Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
            query = "SELECT %s FROM %s" % (queries[Backend.getIdentifiedDbms()].count.query % '*', safeSQLIdentificatorNaming(table, True))
        else:
            query = "SELECT %s FROM %s.%s" % (queries[Backend.getIdentifiedDbms()].count.query % '*', safeSQLIdentificatorNaming(db), safeSQLIdentificatorNaming(table, True))

        count = inject.getValue(query, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

        if isNumPosStrValue(count):
            if safeSQLIdentificatorNaming(db) not in kb.data.cachedCounts:
                kb.data.cachedCounts[safeSQLIdentificatorNaming(db)] = {}

            if int(count) in kb.data.cachedCounts[safeSQLIdentificatorNaming(db)]:
                kb.data.cachedCounts[safeSQLIdentificatorNaming(db)][int(count)].append(safeSQLIdentificatorNaming(table, True))
            else:
                kb.data.cachedCounts[safeSQLIdentificatorNaming(db)][int(count)] = [safeSQLIdentificatorNaming(table, True)]

    def getCount(self):
        if not conf.tbl:
            warnMsg = "missing table parameter, sqlmap will retrieve "
            warnMsg += "the number of entries for all database "
            warnMsg += "management system databases' tables"
            logger.warn(warnMsg)

        elif "." in conf.tbl:
            if not conf.db:
                conf.db, conf.tbl = conf.tbl.split(".")

        if conf.tbl is not None and conf.db is None and Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
            warnMsg = "missing database parameter. sqlmap is going to "
            warnMsg += "use the current database to retrieve the "
            warnMsg += "number of entries for table '%s'" % unsafeSQLIdentificatorNaming(conf.tbl)
            logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

        self.forceDbmsEnum()

        if conf.tbl:
            for table in conf.tbl.split(","):
                self._tableGetCount(conf.db, table)
        else:
            self.getTables()

            for db, tables in kb.data.cachedTables.items():
                for table in tables:
                    self._tableGetCount(db, table)

        return kb.data.cachedCounts
