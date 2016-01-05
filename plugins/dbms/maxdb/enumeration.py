#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import CURRENT_DB
from lib.utils.pivotdumptable import pivotDumpTable
from lib.techniques.brute.use import columnExists
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

        kb.data.processChar = lambda x: x.replace('_', ' ') if x else x

    def getPasswordHashes(self):
        warnMsg = "on SAP MaxDB it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}

    def getDbs(self):
        if len(kb.data.cachedDbs) > 0:
            return kb.data.cachedDbs

        infoMsg = "fetching database names"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].dbs
        randStr = randomStr()
        query = rootQuery.inband.query
        retVal = pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.schemaname' % randStr], blind=True)

        if retVal:
            kb.data.cachedDbs = retVal[0].values()[0]

        if kb.data.cachedDbs:
            kb.data.cachedDbs.sort()

        return kb.data.cachedDbs

    def getTables(self, bruteForce=None):
        if len(kb.data.cachedTables) > 0:
            return kb.data.cachedTables

        self.forceDbmsEnum()

        if conf.db == CURRENT_DB:
            conf.db = self.getCurrentDb()

        if conf.db:
            dbs = conf.db.split(",")
        else:
            dbs = self.getDbs()

        for db in filter(None, dbs):
            dbs[dbs.index(db)] = safeSQLIdentificatorNaming(db)

        infoMsg = "fetching tables for database"
        infoMsg += "%s: %s" % ("s" if len(dbs) > 1 else "", ", ".join(db if isinstance(db, basestring) else db[0] for db in sorted(dbs)))
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].tables

        for db in dbs:
            randStr = randomStr()
            query = rootQuery.inband.query % (("'%s'" % db) if db != "USER" else 'USER')
            retVal = pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.tablename' % randStr], blind=True)

            if retVal:
                for table in retVal[0].values()[0]:
                    if db not in kb.data.cachedTables:
                        kb.data.cachedTables[db] = [table]
                    else:
                        kb.data.cachedTables[db].append(table)

        for db, tables in kb.data.cachedTables.items():
            kb.data.cachedTables[db] = sorted(tables) if tables else tables

        return kb.data.cachedTables

    def getColumns(self, onlyColNames=False, colTuple=None, bruteForce=None, dumpMode=False):
        self.forceDbmsEnum()

        if conf.db is None or conf.db == CURRENT_DB:
            if conf.db is None:
                warnMsg = "missing database parameter. sqlmap is going "
                warnMsg += "to use the current database to enumerate "
                warnMsg += "table(s) columns"
                logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

        elif conf.db is not None:
            if  ',' in conf.db:
                errMsg = "only one database name is allowed when enumerating "
                errMsg += "the tables' columns"
                raise SqlmapMissingMandatoryOptionException(errMsg)

        conf.db = safeSQLIdentificatorNaming(conf.db)

        if conf.col:
            colList = conf.col.split(",")
        else:
            colList = []

        if conf.excludeCol:
            colList = [_ for _ in colList if _ not in conf.excludeCol.split(',')]

        for col in colList:
            colList[colList.index(col)] = safeSQLIdentificatorNaming(col)

        if conf.tbl:
            tblList = conf.tbl.split(",")
        else:
            self.getTables()

            if len(kb.data.cachedTables) > 0:
                tblList = kb.data.cachedTables.values()

                if isinstance(tblList[0], (set, tuple, list)):
                    tblList = tblList[0]
            else:
                errMsg = "unable to retrieve the tables "
                errMsg += "on database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                raise SqlmapNoneDataException(errMsg)

        for tbl in tblList:
            tblList[tblList.index(tbl)] = safeSQLIdentificatorNaming(tbl, True)

        if bruteForce:
            resumeAvailable = False

            for tbl in tblList:
                for db, table, colName, colType in kb.brute.columns:
                    if db == conf.db and table == tbl:
                        resumeAvailable = True
                        break

            if resumeAvailable and not conf.freshQueries or colList:
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

            message = "do you want to use common column existence check? [y/N/q] "
            test = readInput(message, default="Y" if "Y" in message else "N")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise SqlmapUserQuitException
            else:
                return columnExists(paths.COMMON_COLUMNS)

        rootQuery = queries[Backend.getIdentifiedDbms()].columns

        for tbl in tblList:
            if conf.db is not None and len(kb.data.cachedColumns) > 0 \
              and conf.db in kb.data.cachedColumns and tbl in \
              kb.data.cachedColumns[conf.db]:
                infoMsg = "fetched tables' columns on "
                infoMsg += "database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                logger.info(infoMsg)

                return {conf.db: kb.data.cachedColumns[conf.db]}

            if dumpMode and colList:
                table = {}
                table[safeSQLIdentificatorNaming(tbl)] = dict((_, None) for _ in colList)
                kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = table
                continue

            infoMsg = "fetching columns "
            infoMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
            infoMsg += "on database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
            logger.info(infoMsg)

            randStr = randomStr()
            query = rootQuery.inband.query % (unsafeSQLIdentificatorNaming(tbl), ("'%s'" % unsafeSQLIdentificatorNaming(conf.db)) if unsafeSQLIdentificatorNaming(conf.db) != "USER" else 'USER')
            retVal = pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.columnname' % randStr, '%s.datatype' % randStr, '%s.len' % randStr], blind=True)

            if retVal:
                table = {}
                columns = {}

                for columnname, datatype, length in zip(retVal[0]["%s.columnname" % randStr], retVal[0]["%s.datatype" % randStr], retVal[0]["%s.len" % randStr]):
                    columns[safeSQLIdentificatorNaming(columnname)] = "%s(%s)" % (datatype, length)

                table[tbl] = columns
                kb.data.cachedColumns[conf.db] = table

        return kb.data.cachedColumns

    def getPrivileges(self, *args):
        warnMsg = "on SAP MaxDB it is not possible to enumerate the user privileges"
        logger.warn(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "on SAP MaxDB it is not possible to search databases"
        logger.warn(warnMsg)

        return []

    def getHostname(self):
        warnMsg = "on SAP MaxDB it is not possible to enumerate the hostname"
        logger.warn(warnMsg)
