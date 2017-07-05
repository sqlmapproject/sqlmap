#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import filterPairValues
from lib.core.common import getLimitRange
from lib.core.common import getUnicode
from lib.core.common import isAdminFromPrivileges
from lib.core.common import isInferenceAvailable
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import parsePasswordHash
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import unArrayizeValue
from lib.core.convert import hexencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dicts import DB2_PRIVS
from lib.core.dicts import FIREBIRD_PRIVS
from lib.core.dicts import INFORMIX_PRIVS
from lib.core.dicts import MYSQL_PRIVS
from lib.core.dicts import PGSQL_PRIVS
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUserQuitException
from lib.core.threads import getCurrentThreadData
from lib.request import inject
from lib.utils.hash import attackCachedUsersPasswords
from lib.utils.hash import storeHashesToFile
from lib.utils.pivotdumptable import pivotDumpTable

class Users:
    """
    This class defines users' enumeration functionalities for plugins.
    """

    def __init__(self):
        kb.data.currentUser = ""
        kb.data.isDba = None
        kb.data.cachedUsers = []
        kb.data.cachedUsersPasswords = {}
        kb.data.cachedUsersPrivileges = {}
        kb.data.cachedUsersRoles = {}

    def getCurrentUser(self):
        infoMsg = "fetching current user"
        logger.info(infoMsg)

        query = queries[Backend.getIdentifiedDbms()].current_user.query

        if not kb.data.currentUser:
            kb.data.currentUser = unArrayizeValue(inject.getValue(query))

        return kb.data.currentUser

    def isDba(self, user=None):
        infoMsg = "testing if current user is DBA"
        logger.info(infoMsg)

        if Backend.isDbms(DBMS.MYSQL):
            self.getCurrentUser()
            query = queries[Backend.getIdentifiedDbms()].is_dba.query % (kb.data.currentUser.split("@")[0] if kb.data.currentUser else None)
        elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE) and user is not None:
            query = queries[Backend.getIdentifiedDbms()].is_dba.query2 % user
        else:
            query = queries[Backend.getIdentifiedDbms()].is_dba.query

        query = agent.forgeCaseStatement(query)
        kb.data.isDba = inject.checkBooleanExpression(query) or False

        return kb.data.isDba

    def getUsers(self):
        infoMsg = "fetching database users"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].users

        condition = (Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")))
        condition |= (Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema)

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            if condition:
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query
            values = inject.getValue(query, blind=False, time=False)

            if not isNoneValue(values):
                kb.data.cachedUsers = []
                for value in arrayizeValue(values):
                    value = unArrayizeValue(value)
                    if not isNoneValue(value):
                        kb.data.cachedUsers.append(value)

        if not kb.data.cachedUsers and isInferenceAvailable() and not conf.direct:
            infoMsg = "fetching number of database users"
            logger.info(infoMsg)

            if condition:
                query = rootQuery.blind.count2
            else:
                query = rootQuery.blind.count

            count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if count == 0:
                return kb.data.cachedUsers
            elif not isNumPosStrValue(count):
                errMsg = "unable to retrieve the number of database users"
                raise SqlmapNoneDataException(errMsg)

            plusOne = Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2)
            indexRange = getLimitRange(count, plusOne=plusOne)

            for index in indexRange:
                if Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MAXDB):
                    query = rootQuery.blind.query % (kb.data.cachedUsers[-1] if kb.data.cachedUsers else " ")
                elif condition:
                    query = rootQuery.blind.query2 % index
                else:
                    query = rootQuery.blind.query % index
                user = unArrayizeValue(inject.getValue(query, union=False, error=False))

                if user:
                    kb.data.cachedUsers.append(user)

        if not kb.data.cachedUsers:
            errMsg = "unable to retrieve the database users"
            logger.error(errMsg)

        return kb.data.cachedUsers

    def getPasswordHashes(self):
        infoMsg = "fetching database users password hashes"

        rootQuery = queries[Backend.getIdentifiedDbms()].passwords

        if conf.user == "CU":
            infoMsg += " for current user"
            conf.user = self.getCurrentUser()

        logger.info(infoMsg)

        if conf.user and Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
            conf.user = conf.user.upper()

        if conf.user:
            users = conf.user.split(',')

            if Backend.isDbms(DBMS.MYSQL):
                for user in users:
                    parsedUser = re.search("[\047]*(.*?)[\047]*\@", user)

                    if parsedUser:
                        users[users.index(user)] = parsedUser.groups()[0]
        else:
            users = []

        users = filter(None, users)

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            if Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query

            condition = rootQuery.inband.condition

            if conf.user:
                query += " WHERE "
                query += " OR ".join("%s = '%s'" % (condition, user) for user in sorted(users))

            if Backend.isDbms(DBMS.SYBASE):
                randStr = randomStr()
                getCurrentThreadData().disableStdOut = True

                retVal = pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr, '%s.password' % randStr], blind=False)

                if retVal:
                    for user, password in filterPairValues(zip(retVal[0]["%s.name" % randStr], retVal[0]["%s.password" % randStr])):
                        if user not in kb.data.cachedUsersPasswords:
                            kb.data.cachedUsersPasswords[user] = [password]
                        else:
                            kb.data.cachedUsersPasswords[user].append(password)

                getCurrentThreadData().disableStdOut = False
            else:
                values = inject.getValue(query, blind=False, time=False)

                for user, password in filterPairValues(values):
                    if not user or user == " ":
                        continue

                    password = parsePasswordHash(password)

                    if user not in kb.data.cachedUsersPasswords:
                        kb.data.cachedUsersPasswords[user] = [password]
                    else:
                        kb.data.cachedUsersPasswords[user].append(password)

        if not kb.data.cachedUsersPasswords and isInferenceAvailable() and not conf.direct:
            if not len(users):
                users = self.getUsers()

                if Backend.isDbms(DBMS.MYSQL):
                    for user in users:
                        parsedUser = re.search("[\047]*(.*?)[\047]*\@", user)

                        if parsedUser:
                            users[users.index(user)] = parsedUser.groups()[0]

            if Backend.isDbms(DBMS.SYBASE):
                getCurrentThreadData().disableStdOut = True

                randStr = randomStr()
                query = rootQuery.inband.query

                retVal = pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr, '%s.password' % randStr], blind=True)

                if retVal:
                    for user, password in filterPairValues(zip(retVal[0]["%s.name" % randStr], retVal[0]["%s.password" % randStr])):
                        password = "0x%s" % hexencode(password).upper()

                        if user not in kb.data.cachedUsersPasswords:
                            kb.data.cachedUsersPasswords[user] = [password]
                        else:
                            kb.data.cachedUsersPasswords[user].append(password)

                getCurrentThreadData().disableStdOut = False
            else:
                retrievedUsers = set()

                for user in users:
                    user = unArrayizeValue(user)

                    if user in retrievedUsers:
                        continue

                    if Backend.isDbms(DBMS.INFORMIX):
                        count = 1
                    else:
                        infoMsg = "fetching number of password hashes "
                        infoMsg += "for user '%s'" % user
                        logger.info(infoMsg)

                        if Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
                            query = rootQuery.blind.count2 % user
                        else:
                            query = rootQuery.blind.count % user

                        count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                        if not isNumPosStrValue(count):
                            warnMsg = "unable to retrieve the number of password "
                            warnMsg += "hashes for user '%s'" % user
                            logger.warn(warnMsg)
                            continue

                    infoMsg = "fetching password hashes for user '%s'" % user
                    logger.info(infoMsg)

                    passwords = []

                    plusOne = Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2)
                    indexRange = getLimitRange(count, plusOne=plusOne)

                    for index in indexRange:
                        if Backend.isDbms(DBMS.MSSQL):
                            if Backend.isVersionWithin(("2005", "2008")):
                                query = rootQuery.blind.query2 % (user, index, user)
                            else:
                                query = rootQuery.blind.query % (user, index, user)
                        elif Backend.isDbms(DBMS.INFORMIX):
                            query = rootQuery.blind.query % (user,)
                        else:
                            query = rootQuery.blind.query % (user, index)

                        password = unArrayizeValue(inject.getValue(query, union=False, error=False))
                        password = parsePasswordHash(password)

                        passwords.append(password)

                    if passwords:
                        kb.data.cachedUsersPasswords[user] = passwords
                    else:
                        warnMsg = "unable to retrieve the password "
                        warnMsg += "hashes for user '%s'" % user
                        logger.warn(warnMsg)

                    retrievedUsers.add(user)

        if not kb.data.cachedUsersPasswords:
            errMsg = "unable to retrieve the password hashes for the "
            errMsg += "database users (probably because the session "
            errMsg += "user has no read privileges over the relevant "
            errMsg += "system database table)"
            logger.error(errMsg)
        else:
            for user in kb.data.cachedUsersPasswords:
                kb.data.cachedUsersPasswords[user] = list(set(kb.data.cachedUsersPasswords[user]))

            storeHashesToFile(kb.data.cachedUsersPasswords)

            message = "do you want to perform a dictionary-based attack "
            message += "against retrieved password hashes? [Y/n/q]"
            choice = readInput(message, default='Y').upper()

            if choice == 'N':
                pass
            elif choice == 'Q':
                raise SqlmapUserQuitException
            else:
                attackCachedUsersPasswords()

        return kb.data.cachedUsersPasswords

    def getPrivileges(self, query2=False):
        infoMsg = "fetching database users privileges"

        rootQuery = queries[Backend.getIdentifiedDbms()].privileges

        if conf.user == "CU":
            infoMsg += " for current user"
            conf.user = self.getCurrentUser()

        logger.info(infoMsg)

        if conf.user and Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
            conf.user = conf.user.upper()

        if conf.user:
            users = conf.user.split(',')

            if Backend.isDbms(DBMS.MYSQL):
                for user in users:
                    parsedUser = re.search("[\047]*(.*?)[\047]*\@", user)

                    if parsedUser:
                        users[users.index(user)] = parsedUser.groups()[0]
        else:
            users = []

        users = filter(None, users)

        # Set containing the list of DBMS administrators
        areAdmins = set()

        if not kb.data.cachedUsersPrivileges and any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                query = rootQuery.inband.query2
                condition = rootQuery.inband.condition2
            elif Backend.isDbms(DBMS.ORACLE) and query2:
                query = rootQuery.inband.query2
                condition = rootQuery.inband.condition2
            else:
                query = rootQuery.inband.query
                condition = rootQuery.inband.condition

            if conf.user:
                query += " WHERE "

                if Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                    query += " OR ".join("%s LIKE '%%%s%%'" % (condition, user) for user in sorted(users))
                else:
                    query += " OR ".join("%s = '%s'" % (condition, user) for user in sorted(users))

            values = inject.getValue(query, blind=False, time=False)

            if not values and Backend.isDbms(DBMS.ORACLE) and not query2:
                infoMsg = "trying with table USER_SYS_PRIVS"
                logger.info(infoMsg)

                return self.getPrivileges(query2=True)

            if not isNoneValue(values):
                for value in values:
                    user = None
                    privileges = set()

                    for count in xrange(0, len(value or [])):
                        # The first column is always the username
                        if count == 0:
                            user = value[count]

                        # The other columns are the privileges
                        else:
                            privilege = value[count]

                            if privilege is None:
                                continue

                            # In PostgreSQL we get 1 if the privilege is
                            # True, 0 otherwise
                            if Backend.isDbms(DBMS.PGSQL) and getUnicode(privilege).isdigit():
                                if int(privilege) == 1:
                                    privileges.add(PGSQL_PRIVS[count])

                            # In MySQL >= 5.0 and Oracle we get the list
                            # of privileges as string
                            elif Backend.isDbms(DBMS.ORACLE) or (Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema):
                                privileges.add(privilege)

                            # In MySQL < 5.0 we get Y if the privilege is
                            # True, N otherwise
                            elif Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                                if privilege.upper() == "Y":
                                    privileges.add(MYSQL_PRIVS[count])

                            # In Firebird we get one letter for each privilege
                            elif Backend.isDbms(DBMS.FIREBIRD):
                                if privilege.strip() in FIREBIRD_PRIVS:
                                    privileges.add(FIREBIRD_PRIVS[privilege.strip()])

                            # In DB2 we get Y or G if the privilege is
                            # True, N otherwise
                            elif Backend.isDbms(DBMS.DB2):
                                privs = privilege.split(',')
                                privilege = privs[0]
                                if len(privs) > 1:
                                    privs = privs[1]
                                    privs = list(privs.strip())
                                    i = 1

                                    for priv in privs:
                                        if priv.upper() in ("Y", "G"):
                                            for position, db2Priv in DB2_PRIVS.items():
                                                if position == i:
                                                    privilege += ", " + db2Priv

                                        i += 1

                                privileges.add(privilege)

                    if user in kb.data.cachedUsersPrivileges:
                        kb.data.cachedUsersPrivileges[user] = list(privileges.union(kb.data.cachedUsersPrivileges[user]))
                    else:
                        kb.data.cachedUsersPrivileges[user] = list(privileges)

        if not kb.data.cachedUsersPrivileges and isInferenceAvailable() and not conf.direct:
            if Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                conditionChar = "LIKE"
            else:
                conditionChar = "="

            if not len(users):
                users = self.getUsers()

                if Backend.isDbms(DBMS.MYSQL):
                    for user in users:
                        parsedUser = re.search("[\047]*(.*?)[\047]*\@", user)

                        if parsedUser:
                            users[users.index(user)] = parsedUser.groups()[0]

            retrievedUsers = set()

            for user in users:
                outuser = user
                if user in retrievedUsers:
                    continue

                if Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                    user = "%%%s%%" % user

                if Backend.isDbms(DBMS.INFORMIX):
                    count = 1
                else:
                    infoMsg = "fetching number of privileges "
                    infoMsg += "for user '%s'" % outuser
                    logger.info(infoMsg)

                    if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        query = rootQuery.blind.count2 % user
                    elif Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                        query = rootQuery.blind.count % (conditionChar, user)
                    elif Backend.isDbms(DBMS.ORACLE) and query2:
                        query = rootQuery.blind.count2 % user
                    else:
                        query = rootQuery.blind.count % user

                    count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                    if not isNumPosStrValue(count):
                        if not retrievedUsers and Backend.isDbms(DBMS.ORACLE) and not query2:
                            infoMsg = "trying with table USER_SYS_PRIVS"
                            logger.info(infoMsg)

                            return self.getPrivileges(query2=True)

                        warnMsg = "unable to retrieve the number of "
                        warnMsg += "privileges for user '%s'" % outuser
                        logger.warn(warnMsg)
                        continue

                infoMsg = "fetching privileges for user '%s'" % outuser
                logger.info(infoMsg)

                privileges = set()

                plusOne = Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2)
                indexRange = getLimitRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2 % (user, index)
                    elif Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                        query = rootQuery.blind.query % (conditionChar, user, index)
                    elif Backend.isDbms(DBMS.ORACLE) and query2:
                        query = rootQuery.blind.query2 % (user, index)
                    elif Backend.isDbms(DBMS.FIREBIRD):
                        query = rootQuery.blind.query % (index, user)
                    elif Backend.isDbms(DBMS.INFORMIX):
                        query = rootQuery.blind.query % (user,)
                    else:
                        query = rootQuery.blind.query % (user, index)

                    privilege = unArrayizeValue(inject.getValue(query, union=False, error=False))

                    if privilege is None:
                        continue

                    # In PostgreSQL we get 1 if the privilege is True,
                    # 0 otherwise
                    if Backend.isDbms(DBMS.PGSQL) and ", " in privilege:
                        privilege = privilege.replace(", ", ',')
                        privs = privilege.split(',')
                        i = 1

                        for priv in privs:
                            if priv.isdigit() and int(priv) == 1:
                                for position, pgsqlPriv in PGSQL_PRIVS.items():
                                    if position == i:
                                        privileges.add(pgsqlPriv)

                            i += 1

                    # In MySQL >= 5.0 and Oracle we get the list
                    # of privileges as string
                    elif Backend.isDbms(DBMS.ORACLE) or (Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema):
                        privileges.add(privilege)

                    # In MySQL < 5.0 we get Y if the privilege is
                    # True, N otherwise
                    elif Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        privilege = privilege.replace(", ", ',')
                        privs = privilege.split(',')
                        i = 1

                        for priv in privs:
                            if priv.upper() == 'Y':
                                for position, mysqlPriv in MYSQL_PRIVS.items():
                                    if position == i:
                                        privileges.add(mysqlPriv)

                            i += 1

                    # In Firebird we get one letter for each privilege
                    elif Backend.isDbms(DBMS.FIREBIRD):
                        privileges.add(FIREBIRD_PRIVS[privilege.strip()])

                    # In Informix we get one letter for the highest privilege
                    elif Backend.isDbms(DBMS.INFORMIX):
                        privileges.add(INFORMIX_PRIVS[privilege.strip()])

                    # In DB2 we get Y or G if the privilege is
                    # True, N otherwise
                    elif Backend.isDbms(DBMS.DB2):
                        privs = privilege.split(',')
                        privilege = privs[0]
                        privs = privs[1]
                        privs = list(privs.strip())
                        i = 1

                        for priv in privs:
                            if priv.upper() in ('Y', 'G'):
                                for position, db2Priv in DB2_PRIVS.items():
                                    if position == i:
                                        privilege += ", " + db2Priv

                            i += 1

                        privileges.add(privilege)

                    # In MySQL < 5.0 we break the cycle after the first
                    # time we get the user's privileges otherwise we
                    # duplicate the same query
                    if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        break

                if privileges:
                    kb.data.cachedUsersPrivileges[user] = list(privileges)
                else:
                    warnMsg = "unable to retrieve the privileges "
                    warnMsg += "for user '%s'" % outuser
                    logger.warn(warnMsg)

                retrievedUsers.add(user)

        if not kb.data.cachedUsersPrivileges:
            errMsg = "unable to retrieve the privileges "
            errMsg += "for the database users"
            raise SqlmapNoneDataException(errMsg)

        for user, privileges in kb.data.cachedUsersPrivileges.items():
            if isAdminFromPrivileges(privileges):
                areAdmins.add(user)

        return (kb.data.cachedUsersPrivileges, areAdmins)

    def getRoles(self, query2=False):
        warnMsg = "on %s the concept of roles does not " % Backend.getIdentifiedDbms()
        warnMsg += "exist. sqlmap will enumerate privileges instead"
        logger.warn(warnMsg)

        return self.getPrivileges(query2)
