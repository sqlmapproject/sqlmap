#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import Backend
from lib.core.common import isTechniqueAvailable
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dicts import sybaseTypes
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapMissingMandatoryOptionException
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

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            blinds = [False, True]
        else:
            blinds = [True]

        for blind in blinds:
            retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr], blind=blind)

            if retVal:
                kb.data.cachedUsers = retVal[0].values()[0]
                break

        return kb.data.cachedUsers

    def getColumns(self, onlyColNames=False):
        if not conf.tbl:
            warnMsg = "missing table parameter, sqlmap will enumerate "
            warnMsg += "the whole database management system schema"
            logger.warn(warnMsg)

            return self.getSchema()

        if "." in conf.tbl:
            conf.db, conf.tbl = conf.tbl.split(".")

        self.forceDbmsEnum()

        if not conf.db:
            warnMsg  = "missing database parameter, sqlmap is going to "
            warnMsg += "use the current database to enumerate table "
            warnMsg += "'%s' columns" % conf.tbl
            logger.warn(warnMsg)

            conf.db = self.getCurrentDb()
        rootQuery = queries[Backend.getIdentifiedDbms()].columns

        infoMsg = "fetching columns "
        infoMsg += "for table '%s' " % conf.tbl
        infoMsg += "on database '%s'" % conf.db
        logger.info(infoMsg)

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            blinds = [False, True]
        else:
            blinds = [True]

        for blind in blinds:
            randStr = randomStr()
            query = rootQuery.inband.query % (conf.db, conf.db, conf.db, conf.db, conf.db, conf.db, conf.db, conf.tbl)
            retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr,'%s.usertype' % randStr], blind=blind)

            if retVal:
                table = {}
                columns = {}

                for name, type_ in zip(retVal[0]["%s.name" % randStr], retVal[0]["%s.usertype" % randStr]):
                    columns[name] = sybaseTypes[type_] if type_ else None

                table[conf.tbl] = columns
                kb.data.cachedColumns[conf.db] = table

                break

        return kb.data.cachedColumns

    def getTables(self, bruteForce=None):
        self.forceDbmsEnum()

        infoMsg = "fetching tables"
        if conf.db:
            infoMsg += " for database '%s'" % conf.db
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].tables

        if conf.db:
            if "," in conf.db:
                dbs = conf.db.split(",")
            else:
                dbs = [conf.db]
        else:
            if not len(kb.data.cachedDbs):
                dbs = self.getDbs()
            else:
                dbs = kb.data.cachedDbs

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            blinds = [False, True]
        else:
            blinds = [True]

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

        return kb.data.cachedTables

    def getDbs(self):
        infoMsg = "fetching database names"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].dbs

        randStr = randomStr()
        query = rootQuery.inband.query

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            blinds = [False, True]
        else:
            blinds = [True]

        for blind in blinds:
            retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr], blind=blind)

            if retVal:
                kb.data.cachedDbs = retVal[0].values()[0]
                break

        return kb.data.cachedDbs

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
