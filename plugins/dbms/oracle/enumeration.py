#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import getRange
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import safeSQLIdentificatorNaming
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

    def getRoles(self, query2=False):
        infoMsg = "fetching database users roles"

        rootQuery = queries[Backend.getIdentifiedDbms()].roles

        if conf.user == "CU":
            infoMsg += " for current user"
            conf.user = self.getCurrentUser()

        logger.info(infoMsg)

        # Set containing the list of DBMS administrators
        areAdmins = set()

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            if query2:
                query     = rootQuery.inband.query2
                condition = rootQuery.inband.condition2
            else:
                query     = rootQuery.inband.query
                condition = rootQuery.inband.condition

            if conf.user:
                users = conf.user.split(",")
                query += " WHERE "
                query += " OR ".join("%s = '%s'" % (condition, user) for user in users)

            values = inject.getValue(query, blind=False)

            if not values and not query2:
                infoMsg = "trying with table USER_ROLE_PRIVS"
                logger.info(infoMsg)

                return self.getRoles(query2=True)

            if values:
                for value in values:
                    user  = None
                    roles = set()

                    for count in xrange(0, len(value)):
                        # The first column is always the username
                        if count == 0:
                            user = value[count]

                        # The other columns are the roles
                        else:
                            role = value[count]

                            # In Oracle we get the list of roles as string
                            roles.add(role)

                    if self.__isAdminFromPrivileges(roles):
                        areAdmins.add(user)

                    if kb.data.cachedUsersRoles.has_key(user):
                        kb.data.cachedUsersRoles[user].extend(roles)
                    else:
                        kb.data.cachedUsersRoles[user] = list(roles)

        if not kb.data.cachedUsersRoles and not conf.direct:
            conditionChar = "="

            if conf.user:
                users = conf.user.split(",")
            else:
                if not len(kb.data.cachedUsers):
                    users = self.getUsers()
                else:
                    users = kb.data.cachedUsers

            retrievedUsers = set()

            for user in users:
                unescapedUser = None

                if user in retrievedUsers:
                    continue

                infoMsg  = "fetching number of roles "
                infoMsg += "for user '%s'" % user
                logger.info(infoMsg)

                if unescapedUser:
                    queryUser = unescapedUser
                else:
                    queryUser = user

                if query2:
                    query = rootQuery.blind.count2 % queryUser
                else:
                    query = rootQuery.blind.count % queryUser
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    if not count.isdigit() and not query2:
                        infoMsg = "trying with table USER_SYS_PRIVS"
                        logger.info(infoMsg)

                        return self.getPrivileges(query2=True)

                    warnMsg  = "unable to retrieve the number of "
                    warnMsg += "roles for user '%s'" % user
                    logger.warn(warnMsg)
                    continue

                infoMsg = "fetching roles for user '%s'" % user
                logger.info(infoMsg)

                roles = set()

                indexRange = getRange(count, plusOne=True)

                for index in indexRange:
                    if query2:
                        query = rootQuery.blind.query2 % (queryUser, index)
                    else:
                        query = rootQuery.blind.query % (queryUser, index)
                    role = inject.getValue(query, inband=False, error=False)

                    # In Oracle we get the list of roles as string
                    roles.add(role)

                if roles:
                    kb.data.cachedUsersRoles[user] = list(roles)
                else:
                    warnMsg  = "unable to retrieve the roles "
                    warnMsg += "for user '%s'" % user
                    logger.warn(warnMsg)

                retrievedUsers.add(user)

        if not kb.data.cachedUsersRoles:
            errMsg  = "unable to retrieve the roles "
            errMsg += "for the database users"
            raise sqlmapNoneDataException, errMsg

        return ( kb.data.cachedUsersRoles, areAdmins )

    def searchDb(self):
        warnMsg = "on Oracle it is not possible to search databases"
        logger.warn(warnMsg)

        return []

    def searchColumn(self):
        rootQuery = queries[Backend.getIdentifiedDbms()].search_column
        foundCols = {}
        dbs = { "USERS": {} }
        colList = conf.col.split(",")
        colCond = rootQuery.inband.condition
        colConsider, colCondParam = self.likeOrExact("column")

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

                if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
                    query = rootQuery.inband.query
                    query += colQuery
                    values = inject.getValue(query, blind=False)

                    if values:
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

                    query = rootQuery.blind.count2
                    query += " WHERE %s" % colQuery
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
                        query = rootQuery.blind.query2
                        query += " WHERE %s" % colQuery
                        query = agent.limitQuery(index, query)
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

                            dbs[db][tbl].update(kb.data.cachedColumns[db][tbl])
                            kb.data.cachedColumns = {}
                        else:
                            dbs[db][tbl][column] = None

                        foundCols[column][db].append(tbl)

        self.dumpFoundColumn(dbs, foundCols, colConsider)
