#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import filterPairValues
from lib.core.common import isListLike
from lib.core.common import isTechniqueAvailable
from lib.core.common import readInput
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.dicts import SYBASE_TYPES
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import CURRENT_DB
from lib.utils.brute import columnExists
from lib.utils.pivotdumptable import pivotDumpTable
from plugins.generic.enumeration import Enumeration as GenericEnumeration
from thirdparty import six
from thirdparty.six.moves import zip as _zip

class Enumeration(GenericEnumeration):
    def getUsers(self):
        infoMsg = "fetching database users"
        logger.info(infoMsg)

        rootQuery = queries[DBMS.SYBASE].users

        query = rootQuery.inband.query

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            blinds = (False, True)
        else:
            blinds = (True,)

        for blind in blinds:
            retVal = pivotDumpTable("(%s) AS %s" % (query, kb.aliasName), ['%s.name' % kb.aliasName], blind=blind, alias=kb.aliasName)

            if retVal:
                kb.data.cachedUsers = list(retVal[0].values())[0]
                break

        return kb.data.cachedUsers

    def getPrivileges(self, *args, **kwargs):
        warnMsg = "on Sybase it is not possible to fetch "
        warnMsg += "database users privileges, sqlmap will check whether "
        warnMsg += "or not the database users are database administrators"
        logger.warn(warnMsg)

        users = []
        areAdmins = set()

        if conf.user:
            users = [conf.user]
        elif not len(kb.data.cachedUsers):
            users = self.getUsers()
        else:
            users = kb.data.cachedUsers

        for user in users:
            user = unArrayizeValue(user)

            if user is None:
                continue

            isDba = self.isDba(user)

            if isDba is True:
                areAdmins.add(user)

            kb.data.cachedUsersPrivileges[user] = None

        return (kb.data.cachedUsersPrivileges, areAdmins)

    def getDbs(self):
        if len(kb.data.cachedDbs) > 0:
            return kb.data.cachedDbs

        infoMsg = "fetching database names"
        logger.info(infoMsg)

        rootQuery = queries[DBMS.SYBASE].dbs
        query = rootQuery.inband.query

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            blinds = [False, True]
        else:
            blinds = [True]

        for blind in blinds:
            retVal = pivotDumpTable("(%s) AS %s" % (query, kb.aliasName), ['%s.name' % kb.aliasName], blind=blind, alias=kb.aliasName)

            if retVal:
                kb.data.cachedDbs = next(six.itervalues(retVal[0]))
                break

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
            dbs = conf.db.split(',')
        else:
            dbs = self.getDbs()

        for db in dbs:
            dbs[dbs.index(db)] = safeSQLIdentificatorNaming(db)

        dbs = [_ for _ in dbs if _]

        infoMsg = "fetching tables for database"
        infoMsg += "%s: %s" % ("s" if len(dbs) > 1 else "", ", ".join(db if isinstance(db, six.string_types) else db[0] for db in sorted(dbs)))
        logger.info(infoMsg)

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            blinds = [False, True]
        else:
            blinds = [True]

        rootQuery = queries[DBMS.SYBASE].tables

        for db in dbs:
            for blind in blinds:
                query = rootQuery.inband.query % db
                retVal = pivotDumpTable("(%s) AS %s" % (query, kb.aliasName), ['%s.name' % kb.aliasName], blind=blind, alias=kb.aliasName)

                if retVal:
                    for table in next(six.itervalues(retVal[0])):
                        if db not in kb.data.cachedTables:
                            kb.data.cachedTables[db] = [table]
                        else:
                            kb.data.cachedTables[db].append(table)
                    break

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
            if ',' in conf.db:
                errMsg = "only one database name is allowed when enumerating "
                errMsg += "the tables' columns"
                raise SqlmapMissingMandatoryOptionException(errMsg)

        conf.db = safeSQLIdentificatorNaming(conf.db)

        if conf.col:
            colList = conf.col.split(',')
        else:
            colList = []

        if conf.exclude:
            colList = [_ for _ in colList if re.search(conf.exclude, _, re.I) is None]

        for col in colList:
            colList[colList.index(col)] = safeSQLIdentificatorNaming(col)

        if conf.tbl:
            tblList = conf.tbl.split(',')
        else:
            self.getTables()

            if len(kb.data.cachedTables) > 0:
                tblList = list(six.itervalues(kb.data.cachedTables))

                if tblList and isListLike(tblList[0]):
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
            choice = readInput(message, default='Y' if 'Y' in message else 'N').upper()

            if choice == 'N':
                return
            elif choice == 'Q':
                raise SqlmapUserQuitException
            else:
                return columnExists(paths.COMMON_COLUMNS)

        rootQuery = queries[DBMS.SYBASE].columns

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            blinds = [False, True]
        else:
            blinds = [True]

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
                table[safeSQLIdentificatorNaming(tbl, True)] = dict((_, None) for _ in colList)
                kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = table
                continue

            infoMsg = "fetching columns "
            infoMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
            infoMsg += "on database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
            logger.info(infoMsg)

            for blind in blinds:
                query = rootQuery.inband.query % (conf.db, conf.db, conf.db, conf.db, conf.db, conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl))
                retVal = pivotDumpTable("(%s) AS %s" % (query, kb.aliasName), ['%s.name' % kb.aliasName, '%s.usertype' % kb.aliasName], blind=blind, alias=kb.aliasName)

                if retVal:
                    table = {}
                    columns = {}

                    for name, type_ in filterPairValues(_zip(retVal[0]["%s.name" % kb.aliasName], retVal[0]["%s.usertype" % kb.aliasName])):
                        columns[name] = SYBASE_TYPES.get(int(type_) if hasattr(type_, "isdigit") and type_.isdigit() else type_, type_)

                    table[safeSQLIdentificatorNaming(tbl, True)] = columns
                    kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = table

                    break

        return kb.data.cachedColumns

    def searchDb(self):
        warnMsg = "on Sybase searching of databases is not implemented"
        logger.warn(warnMsg)

        return []

    def searchTable(self):
        warnMsg = "on Sybase searching of tables is not implemented"
        logger.warn(warnMsg)

        return []

    def searchColumn(self):
        warnMsg = "on Sybase searching of columns is not implemented"
        logger.warn(warnMsg)

        return []

    def search(self):
        warnMsg = "on Sybase search option is not available"
        logger.warn(warnMsg)

    def getHostname(self):
        warnMsg = "on Sybase it is not possible to enumerate the hostname"
        logger.warn(warnMsg)

    def getStatements(self):
        warnMsg = "on Sybase it is not possible to enumerate the SQL statements"
        logger.warn(warnMsg)

        return []
