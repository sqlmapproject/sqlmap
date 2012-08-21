#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import filterPairValues
from lib.core.common import isTechniqueAvailable
from lib.core.common import randomStr
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dicts import SYBASE_TYPES
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapNoneDataException
from lib.core.settings import CURRENT_DB
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

    def getUsers(self):
        infoMsg = "fetching database users"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].users

        randStr = randomStr()
        query = rootQuery.inband.query

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
            blinds = (False, True)
        else:
            blinds = (True,)

        for blind in blinds:
            retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr], blind=blind)

            if retVal:
                kb.data.cachedUsers = retVal[0].values()[0]
                break

        return kb.data.cachedUsers

    def getPrivileges(self, *args):
        warnMsg = "on Sybase it is not possible to fetch "
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

    def getDbs(self):
        if len(kb.data.cachedDbs) > 0:
            return kb.data.cachedDbs

        infoMsg = "fetching database names"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].dbs
        randStr = randomStr()
        query = rootQuery.inband.query

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
            blinds = [False, True]
        else:
            blinds = [True]

        for blind in blinds:
            retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr], blind=blind)

            if retVal:
                kb.data.cachedDbs = retVal[0].values()[0]
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
            dbs = conf.db.split(",")
        else:
            dbs = self.getDbs()

        for db in dbs:
            dbs[dbs.index(db)] = safeSQLIdentificatorNaming(db)

        dbs = filter(None, dbs)

        infoMsg = "fetching tables for database"
        infoMsg += "%s: %s" % ("s" if len(dbs) > 1 else "", ", ".join(db if isinstance(db, basestring) else db[0] for db in sorted(dbs)))
        logger.info(infoMsg)

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
            blinds = [False, True]
        else:
            blinds = [True]

        rootQuery = queries[Backend.getIdentifiedDbms()].tables

        for db in dbs:
            for blind in blinds:
                randStr = randomStr()
                query = rootQuery.inband.query % db
                retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr], blind=blind)

                if retVal:
                    for table in retVal[0].values()[0]:
                        if not kb.data.cachedTables.has_key(db):
                            kb.data.cachedTables[db] = [table]
                        else:
                            kb.data.cachedTables[db].append(table)
                    break

        for db, tables in kb.data.cachedTables.items():
            kb.data.cachedTables[db] = sorted(tables) if tables else tables

        return kb.data.cachedTables

    def getColumns(self, onlyColNames=False):
        self.forceDbmsEnum()

        if conf.db is None or conf.db == CURRENT_DB:
            if conf.db is None:
                warnMsg = "missing database parameter, sqlmap is going "
                warnMsg += "to use the current database to enumerate "
                warnMsg += "table(s) columns"
                logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

        elif conf.db is not None:
            if  ',' in conf.db:
                errMsg = "only one database name is allowed when enumerating "
                errMsg += "the tables' columns"
                raise sqlmapMissingMandatoryOptionException, errMsg

        conf.db = safeSQLIdentificatorNaming(conf.db)

        if conf.col:
            colList = conf.col.split(",")
        else:
            colList = []

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
                raise sqlmapNoneDataException, errMsg

        for tbl in tblList:
            tblList[tblList.index(tbl)] = safeSQLIdentificatorNaming(tbl)

        rootQuery = queries[Backend.getIdentifiedDbms()].columns

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
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

            if colList:
                table = {}
                table[safeSQLIdentificatorNaming(tbl)] = dict(map(lambda x: (x, None), colList))
                kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = table
                continue

            infoMsg = "fetching columns "
            infoMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
            infoMsg += "on database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
            logger.info(infoMsg)

            for blind in blinds:
                randStr = randomStr()
                query = rootQuery.inband.query % (conf.db, conf.db, conf.db, conf.db, conf.db, conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl))
                retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr,'%s.usertype' % randStr], blind=blind)

                if retVal:
                    table = {}
                    columns = {}

                    for name, type_ in filterPairValues(zip(retVal[0]["%s.name" % randStr], retVal[0]["%s.usertype" % randStr])):
                        columns[name] = sybaseTypes.get(type_, type_)

                    table[safeSQLIdentificatorNaming(tbl)] = columns
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
