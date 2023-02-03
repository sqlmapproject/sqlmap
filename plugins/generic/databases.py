#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import filterNone
from lib.core.common import filterPairValues
from lib.core.common import flattenValue
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
from lib.core.common import safeStringFormat
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.decorators import stackedmethod
from lib.core.dicts import ALTIBASE_TYPES
from lib.core.dicts import FIREBIRD_TYPES
from lib.core.dicts import INFORMIX_TYPES
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import FORK
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import CURRENT_DB
from lib.core.settings import METADB_SUFFIX
from lib.core.settings import PLUS_ONE_DBMSES
from lib.core.settings import REFLECTED_VALUE_MARKER
from lib.core.settings import UPPER_CASE_DBMSES
from lib.core.settings import VERTICA_DEFAULT_SCHEMA
from lib.request import inject
from lib.utils.brute import columnExists
from lib.utils.brute import tableExists
from thirdparty import six

class Databases(object):
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
        kb.data.cachedStatements = []

    def getCurrentDb(self):
        infoMsg = "fetching current database"
        logger.info(infoMsg)

        query = queries[Backend.getIdentifiedDbms()].current_db.query

        if not kb.data.currentDb:
            kb.data.currentDb = unArrayizeValue(inject.getValue(query, safeCharEncode=False))

        if not kb.data.currentDb and Backend.isDbms(DBMS.VERTICA):
            kb.data.currentDb = VERTICA_DEFAULT_SCHEMA

        if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.PGSQL, DBMS.MONETDB, DBMS.DERBY, DBMS.VERTICA, DBMS.PRESTO, DBMS.MIMERSQL, DBMS.CRATEDB, DBMS.CACHE, DBMS.FRONTBASE, DBMS.CLICKHOUSE):
            warnMsg = "on %s you'll need to use " % Backend.getIdentifiedDbms()
            warnMsg += "schema names for enumeration as the counterpart to database "
            warnMsg += "names on other DBMSes"
            singleTimeWarnMessage(warnMsg)
        elif Backend.getIdentifiedDbms() in (DBMS.ALTIBASE, DBMS.CUBRID):
            warnMsg = "on %s you'll need to use " % Backend.getIdentifiedDbms()
            warnMsg += "user names for enumeration as the counterpart to database "
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
            logger.warning(warnMsg)

        elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.PGSQL, DBMS.MONETDB, DBMS.DERBY, DBMS.VERTICA, DBMS.PRESTO, DBMS.MIMERSQL, DBMS.CRATEDB, DBMS.CACHE, DBMS.FRONTBASE, DBMS.CLICKHOUSE):
            warnMsg = "schema names are going to be used on %s " % Backend.getIdentifiedDbms()
            warnMsg += "for enumeration as the counterpart to database "
            warnMsg += "names on other DBMSes"
            logger.warning(warnMsg)

            infoMsg = "fetching database (schema) names"

        elif Backend.getIdentifiedDbms() in (DBMS.ALTIBASE, DBMS.CUBRID):
            warnMsg = "user names are going to be used on %s " % Backend.getIdentifiedDbms()
            warnMsg += "for enumeration as the counterpart to database "
            warnMsg += "names on other DBMSes"
            logger.warning(warnMsg)

            infoMsg = "fetching database (user) names"

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
                plusOne = Backend.getIdentifiedDbms() in PLUS_ONE_DBMSES
                indexRange = getLimitRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.isDbms(DBMS.SYBASE):
                        query = rootQuery.blind.query % (kb.data.cachedDbs[-1] if kb.data.cachedDbs else " ")
                    elif Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2 % index
                    else:
                        query = rootQuery.blind.query % index

                    db = unArrayizeValue(inject.getValue(query, union=False, error=False))

                    if not isNoneValue(db):
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
            kb.data.cachedDbs = [_ for _ in set(flattenValue(kb.data.cachedDbs)) if _]

        return kb.data.cachedDbs

    def getTables(self, bruteForce=None):
        if len(kb.data.cachedTables) > 0:
            return kb.data.cachedTables

        self.forceDbmsEnum()

        if bruteForce is None:
            if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                warnMsg = "information_schema not available, "
                warnMsg += "back-end DBMS is MySQL < 5.0"
                logger.warning(warnMsg)
                bruteForce = True

            elif Backend.getIdentifiedDbms() in (DBMS.MCKOI, DBMS.EXTREMEDB, DBMS.RAIMA):
                bruteForce = True

            elif Backend.getIdentifiedDbms() in (DBMS.ACCESS,):
                try:
                    tables = self.getTables(False)
                except SqlmapNoneDataException:
                    tables = None

                if not tables:
                    warnMsg = "cannot retrieve table names, "
                    warnMsg += "back-end DBMS is %s" % Backend.getIdentifiedDbms()
                    logger.warning(warnMsg)
                    bruteForce = True
                else:
                    return tables

        if conf.db == CURRENT_DB:
            conf.db = self.getCurrentDb()

        if conf.db and Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
            conf.db = conf.db.upper()

        if conf.db:
            dbs = conf.db.split(',')
        else:
            dbs = self.getDbs()

        dbs = [_ for _ in dbs if _ and _.strip()]

        for db in dbs:
            dbs[dbs.index(db)] = safeSQLIdentificatorNaming(db)

        if bruteForce:
            resumeAvailable = False

            for db, table in kb.brute.tables:
                if db == conf.db:
                    resumeAvailable = True
                    break

            if resumeAvailable and not conf.freshQueries:
                for db, table in kb.brute.tables:
                    if db == conf.db:
                        if conf.db not in kb.data.cachedTables:
                            kb.data.cachedTables[conf.db] = [table]
                        else:
                            kb.data.cachedTables[conf.db].append(table)

                return kb.data.cachedTables

            message = "do you want to use common table existence check? %s " % ("[Y/n/q]" if Backend.getIdentifiedDbms() in (DBMS.ACCESS, DBMS.MCKOI, DBMS.EXTREMEDB) else "[y/N/q]")
            choice = readInput(message, default='Y' if 'Y' in message else 'N').upper()

            if choice == 'N':
                return
            elif choice == 'Q':
                raise SqlmapUserQuitException
            else:
                return tableExists(paths.COMMON_TABLES)

        infoMsg = "fetching tables for database"
        infoMsg += "%s: '%s'" % ("s" if len(dbs) > 1 else "", ", ".join(unsafeSQLIdentificatorNaming(unArrayizeValue(db)) for db in sorted(dbs)))
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].tables

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            values = []

            for query, condition in ((rootQuery.inband.query, getattr(rootQuery.inband, "condition", None)), (getattr(rootQuery.inband, "query2", None), getattr(rootQuery.inband, "condition2", None))):
                if not isNoneValue(values) or not query:
                    break

                if condition:
                    if not Backend.isDbms(DBMS.SQLITE):
                        query += " WHERE %s" % condition

                        if conf.excludeSysDbs:
                            infoMsg = "skipping system database%s '%s'" % ("s" if len(self.excludeDbsList) > 1 else "", ", ".join(unsafeSQLIdentificatorNaming(db) for db in self.excludeDbsList))
                            logger.info(infoMsg)
                            query += " IN (%s)" % ','.join("'%s'" % unsafeSQLIdentificatorNaming(db) for db in sorted(dbs) if db not in self.excludeDbsList)
                        else:
                            query += " IN (%s)" % ','.join("'%s'" % unsafeSQLIdentificatorNaming(db) for db in sorted(dbs))

                    if len(dbs) < 2 and ("%s," % condition) in query:
                        query = query.replace("%s," % condition, "", 1)

                if query:
                    values = inject.getValue(query, blind=False, time=False)

            if not isNoneValue(values):
                values = [_ for _ in arrayizeValue(values) if _]

                if len(values) > 0 and not isListLike(values[0]):
                    values = [(dbs[0], _) for _ in values]

                for db, table in filterPairValues(values):
                    table = unArrayizeValue(table)

                    if not isNoneValue(table):
                        db = safeSQLIdentificatorNaming(db)
                        table = safeSQLIdentificatorNaming(table, True)

                        if conf.getComments:
                            _ = queries[Backend.getIdentifiedDbms()].table_comment
                            if hasattr(_, "query"):
                                if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.DERBY, DBMS.ALTIBASE):
                                    query = _.query % (unsafeSQLIdentificatorNaming(db.upper()), unsafeSQLIdentificatorNaming(table.upper()))
                                else:
                                    query = _.query % (unsafeSQLIdentificatorNaming(db), unsafeSQLIdentificatorNaming(table))

                                comment = unArrayizeValue(inject.getValue(query, blind=False, time=False))
                                if not isNoneValue(comment):
                                    infoMsg = "retrieved comment '%s' for table '%s'" % (comment, unsafeSQLIdentificatorNaming(table))
                                    if METADB_SUFFIX not in db:
                                        infoMsg += " in database '%s'" % unsafeSQLIdentificatorNaming(db)
                                    logger.info(infoMsg)
                            else:
                                warnMsg = "on %s it is not " % Backend.getIdentifiedDbms()
                                warnMsg += "possible to get table comments"
                                singleTimeWarnMessage(warnMsg)

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

                if conf.exclude and re.search(conf.exclude, db, re.I) is not None:
                    infoMsg = "skipping database '%s'" % unsafeSQLIdentificatorNaming(db)
                    singleTimeLogMessage(infoMsg)
                    continue

                for _query, _count in ((rootQuery.blind.query, rootQuery.blind.count), (getattr(rootQuery.blind, "query2", None), getattr(rootQuery.blind, "count2", None))):
                    if _query is None:
                        break

                    infoMsg = "fetching number of tables for "
                    infoMsg += "database '%s'" % unsafeSQLIdentificatorNaming(db)
                    logger.info(infoMsg)

                    if Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.FIREBIRD, DBMS.MAXDB, DBMS.ACCESS, DBMS.MCKOI, DBMS.EXTREMEDB):
                        query = _count % unsafeSQLIdentificatorNaming(db)
                    else:
                        query = _count

                    count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                    if count == 0:
                        warnMsg = "database '%s' " % unsafeSQLIdentificatorNaming(db)
                        warnMsg += "appears to be empty"
                        logger.warning(warnMsg)
                        break

                    elif not isNumPosStrValue(count):
                        warnMsg = "unable to retrieve the number of "
                        warnMsg += "tables for database '%s'" % unsafeSQLIdentificatorNaming(db)
                        singleTimeWarnMessage(warnMsg)
                        continue

                    tables = []

                    plusOne = Backend.getIdentifiedDbms() in PLUS_ONE_DBMSES
                    indexRange = getLimitRange(count, plusOne=plusOne)

                    for index in indexRange:
                        if Backend.isDbms(DBMS.SYBASE):
                            query = _query % (db, (kb.data.cachedTables[-1] if kb.data.cachedTables else " "))
                        elif Backend.getIdentifiedDbms() in (DBMS.MAXDB, DBMS.ACCESS, DBMS.MCKOI, DBMS.EXTREMEDB):
                            query = _query % (kb.data.cachedTables[-1] if kb.data.cachedTables else " ")
                        elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.FIREBIRD):
                            query = _query % index
                        elif Backend.getIdentifiedDbms() in (DBMS.HSQLDB, DBMS.INFORMIX, DBMS.FRONTBASE, DBMS.VIRTUOSO):
                            query = _query % (index, unsafeSQLIdentificatorNaming(db))
                        else:
                            query = _query % (unsafeSQLIdentificatorNaming(db), index)

                        table = unArrayizeValue(inject.getValue(query, union=False, error=False))

                        if not isNoneValue(table):
                            kb.hintValue = table
                            table = safeSQLIdentificatorNaming(table, True)
                            tables.append(table)

                    if tables:
                        kb.data.cachedTables[db] = tables

                        if conf.getComments:
                            for table in tables:
                                _ = queries[Backend.getIdentifiedDbms()].table_comment
                                if hasattr(_, "query"):
                                    if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.DERBY, DBMS.ALTIBASE):
                                        query = _.query % (unsafeSQLIdentificatorNaming(db.upper()), unsafeSQLIdentificatorNaming(table.upper()))
                                    else:
                                        query = _.query % (unsafeSQLIdentificatorNaming(db), unsafeSQLIdentificatorNaming(table))

                                    comment = unArrayizeValue(inject.getValue(query, union=False, error=False))
                                    if not isNoneValue(comment):
                                        infoMsg = "retrieved comment '%s' for table '%s'" % (comment, unsafeSQLIdentificatorNaming(table))
                                        if METADB_SUFFIX not in db:
                                            infoMsg += " in database '%s'" % unsafeSQLIdentificatorNaming(db)
                                        logger.info(infoMsg)
                                else:
                                    warnMsg = "on %s it is not " % Backend.getIdentifiedDbms()
                                    warnMsg += "possible to get table comments"
                                    singleTimeWarnMessage(warnMsg)

                        break
                    else:
                        warnMsg = "unable to retrieve the table names "
                        warnMsg += "for database '%s'" % unsafeSQLIdentificatorNaming(db)
                        logger.warning(warnMsg)

        if isNoneValue(kb.data.cachedTables):
            kb.data.cachedTables.clear()

        if not kb.data.cachedTables:
            errMsg = "unable to retrieve the table names for any database"
            if bruteForce is None:
                logger.error(errMsg)
                return self.getTables(bruteForce=True)
            elif not conf.search:
                raise SqlmapNoneDataException(errMsg)
        else:
            for db, tables in kb.data.cachedTables.items():
                kb.data.cachedTables[db] = sorted(tables) if tables else tables

        if kb.data.cachedTables:
            for db in kb.data.cachedTables:
                kb.data.cachedTables[db] = list(set(kb.data.cachedTables[db]))

        return kb.data.cachedTables

    def getColumns(self, onlyColNames=False, colTuple=None, bruteForce=None, dumpMode=False):
        self.forceDbmsEnum()

        if conf.db is None or conf.db == CURRENT_DB:
            if conf.db is None:
                warnMsg = "missing database parameter. sqlmap is going "
                warnMsg += "to use the current database to enumerate "
                warnMsg += "table(s) columns"
                logger.warning(warnMsg)

            conf.db = self.getCurrentDb()

            if not conf.db:
                errMsg = "unable to retrieve the current "
                errMsg += "database name"
                raise SqlmapNoneDataException(errMsg)

        elif conf.db is not None:
            if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
                conf.db = conf.db.upper()

            if ',' in conf.db:
                errMsg = "only one database name is allowed when enumerating "
                errMsg += "the tables' columns"
                raise SqlmapMissingMandatoryOptionException(errMsg)

        conf.db = safeSQLIdentificatorNaming(conf.db)

        if conf.col:
            if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
                conf.col = conf.col.upper()

            colList = conf.col.split(',')
        else:
            colList = []

        if conf.exclude:
            colList = [_ for _ in colList if re.search(conf.exclude, _, re.I) is None]

        for col in colList:
            colList[colList.index(col)] = safeSQLIdentificatorNaming(col)

        colList = [_ for _ in colList if _]

        if conf.tbl:
            if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
                conf.tbl = conf.tbl.upper()

            tblList = conf.tbl.split(',')
        else:
            self.getTables()

            if len(kb.data.cachedTables) > 0:
                if conf.db in kb.data.cachedTables:
                    tblList = kb.data.cachedTables[conf.db]
                else:
                    tblList = list(six.itervalues(kb.data.cachedTables))

                if tblList and isListLike(tblList[0]):
                    tblList = tblList[0]

                tblList = list(tblList)
            elif not conf.search:
                errMsg = "unable to retrieve the tables"
                if METADB_SUFFIX not in conf.db:
                    errMsg += " in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                raise SqlmapNoneDataException(errMsg)
            else:
                return kb.data.cachedColumns

        if conf.exclude:
            tblList = [_ for _ in tblList if re.search(conf.exclude, _, re.I) is None]

        tblList = filterNone(safeSQLIdentificatorNaming(_, True) for _ in tblList)

        if bruteForce is None:
            if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                warnMsg = "information_schema not available, "
                warnMsg += "back-end DBMS is MySQL < 5.0"
                logger.warning(warnMsg)
                bruteForce = True

            elif Backend.getIdentifiedDbms() in (DBMS.ACCESS, DBMS.MCKOI, DBMS.EXTREMEDB, DBMS.RAIMA):
                warnMsg = "cannot retrieve column names, "
                warnMsg += "back-end DBMS is %s" % Backend.getIdentifiedDbms()
                singleTimeWarnMessage(warnMsg)
                bruteForce = True

        if bruteForce:
            resumeAvailable = False

            for tbl in tblList:
                for db, table, colName, colType in kb.brute.columns:
                    if db == conf.db and table == tbl:
                        resumeAvailable = True
                        break

            if resumeAvailable and not (conf.freshQueries and not colList):
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

            if kb.choices.columnExists is None:
                message = "do you want to use common column existence check? %s" % ("[Y/n/q]" if Backend.getIdentifiedDbms() in (DBMS.ACCESS, DBMS.MCKOI, DBMS.EXTREMEDB) else "[y/N/q]")
                kb.choices.columnExists = readInput(message, default='Y' if 'Y' in message else 'N').upper()

            if kb.choices.columnExists == 'N':
                if dumpMode and colList:
                    kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = {safeSQLIdentificatorNaming(tbl, True): dict((_, None) for _ in colList)}
                    return kb.data.cachedColumns
                else:
                    return None
            elif kb.choices.columnExists == 'Q':
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
                    infoMsg = "fetched table columns from "
                    infoMsg += "database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    logger.info(infoMsg)

                    return {conf.db: kb.data.cachedColumns[conf.db]}

                infoMsg = "fetching columns "
                condQuery = ""

                if len(colList) > 0:
                    if colTuple:
                        _, colCondParam = colTuple
                        infoMsg += "LIKE '%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))
                    else:
                        colCondParam = "='%s'"
                        infoMsg += "'%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))

                    condQueryStr = "%%s%s" % colCondParam
                    condQuery = " AND (%s)" % " OR ".join(condQueryStr % (condition, unsafeSQLIdentificatorNaming(col)) for col in sorted(colList))

                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.HSQLDB, DBMS.H2, DBMS.MONETDB, DBMS.VERTICA, DBMS.PRESTO, DBMS.CRATEDB, DBMS.CUBRID, DBMS.CACHE, DBMS.FRONTBASE, DBMS.VIRTUOSO, DBMS.CLICKHOUSE):
                    query = rootQuery.inband.query % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))
                    query += condQuery

                    if Backend.isDbms(DBMS.MYSQL) and Backend.isFork(FORK.DRIZZLE):
                        query = re.sub("column_type", "data_type", query, flags=re.I)

                elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.DERBY, DBMS.ALTIBASE, DBMS.MIMERSQL):
                    query = rootQuery.inband.query % (unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(conf.db.upper()))
                    query += condQuery

                elif Backend.isDbms(DBMS.MSSQL):
                    query = rootQuery.inband.query % (conf.db, conf.db, conf.db, conf.db,
                                                      conf.db, conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl).split(".")[-1])
                    query += condQuery.replace("[DB]", conf.db)

                elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.FIREBIRD):
                    query = rootQuery.inband.query % unsafeSQLIdentificatorNaming(tbl)

                elif Backend.isDbms(DBMS.INFORMIX):
                    query = rootQuery.inband.query % (conf.db, conf.db, conf.db, conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl))
                    query += condQuery

                if dumpMode and colList:
                    values = [(_,) for _ in colList]
                else:
                    infoMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                    if METADB_SUFFIX not in conf.db:
                        infoMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    logger.info(infoMsg)

                    values = None

                    if values is None:
                        values = inject.getValue(query, blind=False, time=False)
                        if values and isinstance(values[0], six.string_types):
                            values = [values]

                if Backend.isDbms(DBMS.MSSQL) and isNoneValue(values):
                    index, values = 1, []

                    while True:
                        query = rootQuery.inband.query2 % (conf.db, unsafeSQLIdentificatorNaming(tbl), index)
                        value = unArrayizeValue(inject.getValue(query, blind=False, time=False))

                        if isNoneValue(value) or value == " ":
                            break
                        else:
                            values.append((value,))
                            index += 1

                if Backend.isDbms(DBMS.SQLITE):
                    if dumpMode and colList:
                        if conf.db not in kb.data.cachedColumns:
                            kb.data.cachedColumns[conf.db] = {}
                        kb.data.cachedColumns[conf.db][safeSQLIdentificatorNaming(conf.tbl, True)] = dict((_, None) for _ in colList)
                    else:
                        parseSqliteTableSchema(unArrayizeValue(values))

                elif not isNoneValue(values):
                    table = {}
                    columns = {}

                    for columnData in values:
                        if not isNoneValue(columnData):
                            columnData = [unArrayizeValue(_) for _ in columnData]
                            name = safeSQLIdentificatorNaming(columnData[0])

                            if name:
                                if conf.getComments:
                                    _ = queries[Backend.getIdentifiedDbms()].column_comment
                                    if hasattr(_, "query"):
                                        if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
                                            query = _.query % (unsafeSQLIdentificatorNaming(conf.db.upper()), unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(name.upper()))
                                        else:
                                            query = _.query % (unsafeSQLIdentificatorNaming(conf.db), unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(name))

                                        comment = unArrayizeValue(inject.getValue(query, blind=False, time=False))
                                        if not isNoneValue(comment):
                                            infoMsg = "retrieved comment '%s' for column '%s'" % (comment, name)
                                            logger.info(infoMsg)
                                    else:
                                        warnMsg = "on %s it is not " % Backend.getIdentifiedDbms()
                                        warnMsg += "possible to get column comments"
                                        singleTimeWarnMessage(warnMsg)

                                if len(columnData) == 1:
                                    columns[name] = None
                                else:
                                    key = int(columnData[1]) if isinstance(columnData[1], six.string_types) and columnData[1].isdigit() else columnData[1]
                                    if Backend.isDbms(DBMS.FIREBIRD):
                                        columnData[1] = FIREBIRD_TYPES.get(key, columnData[1])
                                    elif Backend.isDbms(DBMS.ALTIBASE):
                                        columnData[1] = ALTIBASE_TYPES.get(key, columnData[1])
                                    elif Backend.isDbms(DBMS.INFORMIX):
                                        notNull = False
                                        if isinstance(key, int) and key > 255:
                                            key -= 256
                                            notNull = True
                                        columnData[1] = INFORMIX_TYPES.get(key, columnData[1])
                                        if notNull:
                                            columnData[1] = "%s NOT NULL" % columnData[1]

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
                    infoMsg = "fetched table columns from "
                    infoMsg += "database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    logger.info(infoMsg)

                    return {conf.db: kb.data.cachedColumns[conf.db]}

                infoMsg = "fetching columns "
                condQuery = ""

                if len(colList) > 0:
                    if colTuple:
                        _, colCondParam = colTuple
                        infoMsg += "LIKE '%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))
                    else:
                        colCondParam = "='%s'"
                        infoMsg += "'%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))

                    condQueryStr = "%%s%s" % colCondParam
                    condQuery = " AND (%s)" % " OR ".join(condQueryStr % (condition, unsafeSQLIdentificatorNaming(col)) for col in sorted(colList))

                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.HSQLDB, DBMS.H2, DBMS.MONETDB, DBMS.VERTICA, DBMS.PRESTO, DBMS.CRATEDB, DBMS.CUBRID, DBMS.CACHE, DBMS.FRONTBASE, DBMS.VIRTUOSO, DBMS.CLICKHOUSE):
                    query = rootQuery.blind.count % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))
                    query += condQuery

                elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.DERBY, DBMS.ALTIBASE, DBMS.MIMERSQL):
                    query = rootQuery.blind.count % (unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(conf.db.upper()))
                    query += condQuery

                elif Backend.isDbms(DBMS.MSSQL):
                    query = rootQuery.blind.count % (conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl).split(".")[-1])
                    query += condQuery.replace("[DB]", conf.db)

                elif Backend.isDbms(DBMS.FIREBIRD):
                    query = rootQuery.blind.count % unsafeSQLIdentificatorNaming(tbl)
                    query += condQuery

                elif Backend.isDbms(DBMS.INFORMIX):
                    query = rootQuery.blind.count % (conf.db, conf.db, conf.db, conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl))
                    query += condQuery

                elif Backend.isDbms(DBMS.SQLITE):
                    if dumpMode and colList:
                        if conf.db not in kb.data.cachedColumns:
                            kb.data.cachedColumns[conf.db] = {}
                        kb.data.cachedColumns[conf.db][safeSQLIdentificatorNaming(conf.tbl, True)] = dict((_, None) for _ in colList)
                    else:
                        query = rootQuery.blind.query % unsafeSQLIdentificatorNaming(tbl)
                        value = unArrayizeValue(inject.getValue(query, union=False, error=False))
                        parseSqliteTableSchema(unArrayizeValue(value))

                    return kb.data.cachedColumns

                table = {}
                columns = {}

                if dumpMode and colList:
                    count = 0
                    for value in colList:
                        columns[safeSQLIdentificatorNaming(value)] = None
                else:
                    infoMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                    if METADB_SUFFIX not in conf.db:
                        infoMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    logger.info(infoMsg)

                    count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                    if not isNumPosStrValue(count):
                        if Backend.isDbms(DBMS.MSSQL):
                            count, index, values = 0, 1, []
                            while True:
                                query = rootQuery.blind.query3 % (conf.db, unsafeSQLIdentificatorNaming(tbl), index)
                                value = unArrayizeValue(inject.getValue(query, union=False, error=False))

                                if isNoneValue(value) or value == " ":
                                    break
                                else:
                                    columns[safeSQLIdentificatorNaming(value)] = None
                                    index += 1

                        if not columns:
                            errMsg = "unable to retrieve the %scolumns " % ("number of " if not Backend.isDbms(DBMS.MSSQL) else "")
                            errMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                            if METADB_SUFFIX not in conf.db:
                                errMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                            logger.error(errMsg)
                            continue

                for index in getLimitRange(count):
                    if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.HSQLDB, DBMS.VERTICA, DBMS.PRESTO, DBMS.CRATEDB, DBMS.CUBRID, DBMS.CACHE, DBMS.FRONTBASE, DBMS.VIRTUOSO):
                        query = rootQuery.blind.query % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))
                        query += condQuery
                        field = None
                    elif Backend.isDbms(DBMS.H2):
                        query = rootQuery.blind.query % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))
                        query = query.replace(" ORDER BY ", "%s ORDER BY " % condQuery)
                        field = None
                    elif Backend.isDbms(DBMS.MIMERSQL):
                        query = rootQuery.blind.query % (unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(conf.db.upper()))
                        query = query.replace(" ORDER BY ", "%s ORDER BY " % condQuery)
                        field = None
                    elif Backend.getIdentifiedDbms() in (DBMS.MONETDB, DBMS.CLICKHOUSE):
                        query = safeStringFormat(rootQuery.blind.query, (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db), index))
                        field = None
                    elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.DERBY, DBMS.ALTIBASE):
                        query = rootQuery.blind.query % (unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(conf.db.upper()))
                        query += condQuery
                        field = None
                    elif Backend.isDbms(DBMS.MSSQL):
                        query = rootQuery.blind.query.replace("'%s'", "'%s'" % unsafeSQLIdentificatorNaming(tbl).split(".")[-1]).replace("%s", conf.db).replace("%d", str(index))
                        query += condQuery.replace("[DB]", conf.db)
                        field = condition.replace("[DB]", conf.db)
                    elif Backend.isDbms(DBMS.FIREBIRD):
                        query = rootQuery.blind.query % unsafeSQLIdentificatorNaming(tbl)
                        query += condQuery
                        field = None
                    elif Backend.isDbms(DBMS.INFORMIX):
                        query = rootQuery.blind.query % (index, conf.db, conf.db, conf.db, conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl))
                        query += condQuery
                        field = condition

                    query = agent.limitQuery(index, query, field, field)
                    column = unArrayizeValue(inject.getValue(query, union=False, error=False))

                    if not isNoneValue(column):
                        if conf.getComments:
                            _ = queries[Backend.getIdentifiedDbms()].column_comment
                            if hasattr(_, "query"):
                                if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
                                    query = _.query % (unsafeSQLIdentificatorNaming(conf.db.upper()), unsafeSQLIdentificatorNaming(tbl.upper()), unsafeSQLIdentificatorNaming(column.upper()))
                                else:
                                    query = _.query % (unsafeSQLIdentificatorNaming(conf.db), unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(column))

                                comment = unArrayizeValue(inject.getValue(query, union=False, error=False))
                                if not isNoneValue(comment):
                                    infoMsg = "retrieved comment '%s' for column '%s'" % (comment, column)
                                    logger.info(infoMsg)
                            else:
                                warnMsg = "on %s it is not " % Backend.getIdentifiedDbms()
                                warnMsg += "possible to get column comments"
                                singleTimeWarnMessage(warnMsg)

                        if not onlyColNames:
                            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL, DBMS.HSQLDB, DBMS.H2, DBMS.VERTICA, DBMS.PRESTO, DBMS.CRATEDB, DBMS.CACHE, DBMS.FRONTBASE, DBMS.VIRTUOSO, DBMS.CLICKHOUSE):
                                query = rootQuery.blind.query2 % (unsafeSQLIdentificatorNaming(tbl), column, unsafeSQLIdentificatorNaming(conf.db))
                            elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2, DBMS.DERBY, DBMS.ALTIBASE, DBMS.MIMERSQL):
                                query = rootQuery.blind.query2 % (unsafeSQLIdentificatorNaming(tbl.upper()), column, unsafeSQLIdentificatorNaming(conf.db.upper()))
                            elif Backend.isDbms(DBMS.MSSQL):
                                query = rootQuery.blind.query2 % (conf.db, conf.db, conf.db, conf.db, column, conf.db, conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl).split(".")[-1])
                            elif Backend.isDbms(DBMS.FIREBIRD):
                                query = rootQuery.blind.query2 % (unsafeSQLIdentificatorNaming(tbl), column)
                            elif Backend.isDbms(DBMS.INFORMIX):
                                query = rootQuery.blind.query2 % (conf.db, conf.db, conf.db, conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl), column)
                            elif Backend.isDbms(DBMS.MONETDB):
                                query = rootQuery.blind.query2 % (column, unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))

                            colType = unArrayizeValue(inject.getValue(query, union=False, error=False))
                            key = int(colType) if hasattr(colType, "isdigit") and colType.isdigit() else colType

                            if Backend.isDbms(DBMS.FIREBIRD):
                                colType = FIREBIRD_TYPES.get(key, colType)
                            elif Backend.isDbms(DBMS.INFORMIX):
                                notNull = False
                                if isinstance(key, int) and key > 255:
                                    key -= 256
                                    notNull = True
                                colType = INFORMIX_TYPES.get(key, colType)
                                if notNull:
                                    colType = "%s NOT NULL" % colType

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
            if METADB_SUFFIX not in conf.db:
                warnMsg += "in database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
            logger.warning(warnMsg)

            if bruteForce is None:
                return self.getColumns(onlyColNames=onlyColNames, colTuple=colTuple, bruteForce=True)

        return kb.data.cachedColumns

    @stackedmethod
    def getSchema(self):
        infoMsg = "enumerating database management system schema"
        logger.info(infoMsg)

        try:
            pushValue(conf.db)
            pushValue(conf.tbl)
            pushValue(conf.col)

            kb.data.cachedTables = {}
            kb.data.cachedColumns = {}

            self.getTables()

            infoMsg = "fetched tables: "
            infoMsg += ", ".join(["%s" % ", ".join("'%s%s%s'" % (unsafeSQLIdentificatorNaming(db), ".." if Backend.isDbms(DBMS.MSSQL) or Backend.isDbms(DBMS.SYBASE) else '.', unsafeSQLIdentificatorNaming(_)) for _ in tbl) for db, tbl in kb.data.cachedTables.items()])
            logger.info(infoMsg)

            for db, tables in kb.data.cachedTables.items():
                for tbl in tables:
                    conf.db = db
                    conf.tbl = tbl

                    self.getColumns()
        finally:
            conf.col = popValue()
            conf.tbl = popValue()
            conf.db = popValue()

        return kb.data.cachedColumns

    def _tableGetCount(self, db, table):
        if not db or not table:
            return None

        if Backend.getIdentifiedDbms() in UPPER_CASE_DBMSES:
            db = db.upper()
            table = table.upper()

        if Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD, DBMS.MCKOI, DBMS.EXTREMEDB):
            query = "SELECT %s FROM %s" % (queries[Backend.getIdentifiedDbms()].count.query % '*', safeSQLIdentificatorNaming(table, True))
        else:
            query = "SELECT %s FROM %s.%s" % (queries[Backend.getIdentifiedDbms()].count.query % '*', safeSQLIdentificatorNaming(db), safeSQLIdentificatorNaming(table, True))

        query = agent.whereQuery(query)
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
            logger.warning(warnMsg)

        elif "." in conf.tbl:
            if not conf.db:
                conf.db, conf.tbl = conf.tbl.split('.', 1)

        if conf.tbl is not None and conf.db is None and Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD, DBMS.MCKOI, DBMS.EXTREMEDB):
            warnMsg = "missing database parameter. sqlmap is going to "
            warnMsg += "use the current database to retrieve the "
            warnMsg += "number of entries for table '%s'" % unsafeSQLIdentificatorNaming(conf.tbl)
            logger.warning(warnMsg)

            conf.db = self.getCurrentDb()

        self.forceDbmsEnum()

        if conf.tbl:
            for table in conf.tbl.split(','):
                self._tableGetCount(conf.db, table)
        else:
            self.getTables()

            for db, tables in kb.data.cachedTables.items():
                for table in tables:
                    self._tableGetCount(db, table)

        return kb.data.cachedCounts

    def getStatements(self):
        infoMsg = "fetching SQL statements"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].statements

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            if Backend.isDbms(DBMS.MYSQL) and Backend.isFork(FORK.DRIZZLE):
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query

            while True:
                values = inject.getValue(query, blind=False, time=False)

                if not isNoneValue(values):
                    kb.data.cachedStatements = []
                    for value in arrayizeValue(values):
                        value = (unArrayizeValue(value) or "").strip()
                        if not isNoneValue(value):
                            kb.data.cachedStatements.append(value.strip())

                elif Backend.isDbms(DBMS.PGSQL) and "current_query" not in query:
                    query = query.replace("query", "current_query")
                    continue

                break

        if not kb.data.cachedStatements and isInferenceAvailable() and not conf.direct:
            infoMsg = "fetching number of statements"
            logger.info(infoMsg)

            query = rootQuery.blind.count

            if Backend.isDbms(DBMS.MYSQL) and Backend.isFork(FORK.DRIZZLE):
                query = re.sub("INFORMATION_SCHEMA", "DATA_DICTIONARY", query, flags=re.I)

            count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if count == 0:
                return kb.data.cachedStatements
            elif not isNumPosStrValue(count):
                errMsg = "unable to retrieve the number of statements"
                raise SqlmapNoneDataException(errMsg)

            plusOne = Backend.getIdentifiedDbms() in PLUS_ONE_DBMSES
            indexRange = getLimitRange(count, plusOne=plusOne)

            for index in indexRange:
                value = None

                if Backend.getIdentifiedDbms() in (DBMS.MYSQL,):  # case with multiple processes
                    query = rootQuery.blind.query3 % index
                    identifier = unArrayizeValue(inject.getValue(query, union=False, error=False, expected=EXPECTED.INT))

                    if not isNoneValue(identifier):
                        query = rootQuery.blind.query2 % identifier
                        value = unArrayizeValue(inject.getValue(query, union=False, error=False, expected=EXPECTED.INT))

                if isNoneValue(value):
                    query = rootQuery.blind.query % index

                    if Backend.isDbms(DBMS.MYSQL) and Backend.isFork(FORK.DRIZZLE):
                        query = re.sub("INFORMATION_SCHEMA", "DATA_DICTIONARY", query, flags=re.I)

                    value = unArrayizeValue(inject.getValue(query, union=False, error=False))

                if not isNoneValue(value):
                    kb.data.cachedStatements.append(value)

        if not kb.data.cachedStatements:
            errMsg = "unable to retrieve the statements"
            logger.error(errMsg)
        else:
            kb.data.cachedStatements = [_.replace(REFLECTED_VALUE_MARKER, "<payload>") for _ in kb.data.cachedStatements]

        return kb.data.cachedStatements
