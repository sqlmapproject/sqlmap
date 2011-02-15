#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import dataToStdout
from lib.core.common import getRange
from lib.core.common import getCompiledRegex
from lib.core.common import getConsoleWidth
from lib.core.common import getFileItems
from lib.core.common import Backend
from lib.core.common import getUnicode
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import parsePasswordHash
from lib.core.common import parseSqliteTableSchema
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import safeStringFormat
from lib.core.common import strToHex
from lib.core.convert import utf8decode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
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
        kb.data.banner                 = None
        kb.data.currentUser            = ""
        kb.data.currentDb              = ""
        kb.data.cachedUsers            = []
        kb.data.cachedUsersPasswords   = {}
        kb.data.cachedUsersPrivileges  = {}
        kb.data.cachedUsersRoles       = {}
        kb.data.cachedDbs              = []
        kb.data.cachedTables           = {}
        kb.data.cachedColumns          = {}
        kb.data.dumpedTable            = {}
        kb.data.processChar            = None
        self.alwaysRetrieveSqlOutput   = False

    def getBanner(self):
        if not conf.getBanner:
            return

        if kb.data.banner is None:
            infoMsg = "fetching banner"
            logger.info(infoMsg)

            query = queries[Backend.getIdentifiedDbms()].banner.query
            kb.data.banner = inject.getValue(query)
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
            kb.data.currentUser = inject.getValue(query)

        return kb.data.currentUser

    def getCurrentDb(self):
        infoMsg = "fetching current database"
        logger.info(infoMsg)

        query = queries[Backend.getIdentifiedDbms()].current_db.query

        if not kb.data.currentDb:
            kb.data.currentDb = inject.getValue(query)

        return kb.data.currentDb

    def isDba(self, user=None):
        infoMsg = "testing if current user is DBA"
        logger.info(infoMsg)

        if Backend.getIdentifiedDbms() == DBMS.MYSQL:
            self.getCurrentUser()
            query = queries[Backend.getIdentifiedDbms()].is_dba.query % kb.data.currentUser.split("@")[0]
        elif Backend.getIdentifiedDbms() == DBMS.MSSQL and user is not None:
            query = queries[Backend.getIdentifiedDbms()].is_dba.query2 % user
        else:
            query = queries[Backend.getIdentifiedDbms()].is_dba.query

        query = agent.forgeCaseStatement(query)
        isDba = inject.getValue(query, unpack=False, charsetType=1)

        if user is None:
            kb.data.isDba = isDba

        return isDba == "1"

    def getUsers(self):
        infoMsg = "fetching database users"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].users

        condition  = ( Backend.getIdentifiedDbms() == DBMS.MSSQL and Backend.isVersionWithin(("2005", "2008")) )
        condition |= ( Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema )

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            if condition:
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query
            value = inject.getValue(query, blind=False)

            if value:
                kb.data.cachedUsers = arrayizeValue(value)

        if not kb.data.cachedUsers and not conf.direct:
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

            if Backend.getIdentifiedDbms() == DBMS.ORACLE:
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

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            if Backend.getIdentifiedDbms() == DBMS.MSSQL and Backend.isVersionWithin(("2005", "2008")):
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query

            condition = rootQuery.inband.condition

            if conf.user:
                if "," in conf.user:
                    users = conf.user.split(",")
                    query += " WHERE "
                    query += " OR ".join("%s = '%s'" % (condition, user) for user in users)
                else:
                    if Backend.getIdentifiedDbms() == DBMS.MYSQL:
                        parsedUser = re.search("[\047]*(.*?)[\047]*\@", conf.user)

                        if parsedUser:
                            conf.user = parsedUser.groups()[0]

                    query += " WHERE %s = '%s'" % (condition, conf.user)

            value = inject.getValue(query, blind=False)

            if value:
                for user, password in value:
                    if not user or user == " ":
                        continue

                    password = parsePasswordHash(password)

                    if not kb.data.cachedUsersPasswords.has_key(user):
                        kb.data.cachedUsersPasswords[user] = [password]
                    else:
                        kb.data.cachedUsersPasswords[user].append(password)

        if not kb.data.cachedUsersPasswords and not conf.direct:
            if conf.user:
                if "," in conf.user:
                    users = conf.user.split(",")
                else:
                    users = [conf.user]
            else:
                if not len(kb.data.cachedUsers):
                    users = self.getUsers()
                else:
                    users = kb.data.cachedUsers

            retrievedUsers = set()

            for user in users:
                if Backend.getIdentifiedDbms() == DBMS.MYSQL:
                    parsedUser = re.search("[\047]*(.*?)[\047]*\@", user)

                    if parsedUser:
                        user = parsedUser.groups()[0]

                if not user or user in retrievedUsers:
                    continue

                infoMsg  = "fetching number of password hashes "
                infoMsg += "for user '%s'" % user
                logger.info(infoMsg)

                if Backend.getIdentifiedDbms() == DBMS.MSSQL and Backend.isVersionWithin(("2005", "2008")):
                    query = rootQuery.blind.count2 % user
                else:
                    query = rootQuery.blind.count % user
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    warnMsg  = "unable to retrieve the number of password "
                    warnMsg += "hashes for user '%s'" % user
                    logger.warn(warnMsg)
                    continue

                infoMsg = "fetching password hashes for user '%s'" % user
                logger.info(infoMsg)

                passwords  = []

                if Backend.getIdentifiedDbms() == DBMS.ORACLE:
                    plusOne = True
                else:
                    plusOne = False
                indexRange = getRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.getIdentifiedDbms() == DBMS.SYBASE:
                        if index > 0:
                            warnMsg  = "unable to retrieve other password "
                            warnMsg += "hashes for user '%s'" % user
                            logger.warn(warnMsg)
                            break
                        else:
                            query = rootQuery.blind.query % user
                            getCurrentThreadData().disableStdOut = True
                    elif Backend.getIdentifiedDbms() == DBMS.MSSQL:
                        if Backend.isVersionWithin(("2005", "2008")):
                            query = rootQuery.blind.query2 % (user, index, user)
                        else:
                            query = rootQuery.blind.query % (user, index, user)
                    else:
                        query = rootQuery.blind.query % (user, index)
                    password = inject.getValue(query, inband=False, error=False)
                    if Backend.getIdentifiedDbms() == DBMS.SYBASE:
                        getCurrentThreadData().disableStdOut = False
                        password = "0x%s" % strToHex(password)
                        infoMsg = "retrieved: %s" % password
                        logger.info(infoMsg)
                    password = parsePasswordHash(password)
                    passwords.append(password)

                if passwords:
                    kb.data.cachedUsersPasswords[user] = passwords
                else:
                    warnMsg  = "unable to retrieve the password "
                    warnMsg += "hashes for user '%s'" % user
                    logger.warn(warnMsg)

                retrievedUsers.add(user)

        if not kb.data.cachedUsersPasswords:
            errMsg  = "unable to retrieve the password "
            errMsg += "hashes for the database users"
            raise sqlmapNoneDataException, errMsg

        message = "do you want to use dictionary attack on retrieved password hashes? [Y/n/q]"
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
        dbaCondition  = ( Backend.getIdentifiedDbms() == DBMS.PGSQL and "super" in privileges )

        # In Oracle the DBA privilege means that the
        # user is DBA
        dbaCondition |= ( Backend.getIdentifiedDbms() == DBMS.ORACLE and "DBA" in privileges )

        # In MySQL >= 5.0 the SUPER privilege means
        # that the user is DBA
        dbaCondition |= ( Backend.getIdentifiedDbms() == DBMS.MYSQL and kb.data.has_information_schema and "SUPER" in privileges )

        # In MySQL < 5.0 the super_priv privilege means
        # that the user is DBA
        dbaCondition |= ( Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema and "super_priv" in privileges )

        # In Firebird there is no specific privilege that means
        # that the user is DBA
        # TODO: confirm
        dbaCondition |= ( Backend.getIdentifiedDbms() == DBMS.FIREBIRD and "SELECT" in privileges and "INSERT" in privileges and "UPDATE" in privileges and "DELETE" in privileges and "REFERENCES" in privileges and "EXECUTE" in privileges )

        return dbaCondition

    def getPrivileges(self, query2=False):
        infoMsg = "fetching database users privileges"

        rootQuery = queries[Backend.getIdentifiedDbms()].privileges

        if conf.user == "CU":
            infoMsg += " for current user"
            conf.user = self.getCurrentUser()

        logger.info(infoMsg)

        # Set containing the list of DBMS administrators
        areAdmins = set()

        mysqlPrivs = (
                        ( 1, "select_priv" ),
                        ( 2, "insert_priv" ),
                        ( 3, "update_priv" ),
                        ( 4, "delete_priv" ),
                        ( 5, "create_priv" ),
                        ( 6, "drop_priv" ),
                        ( 7, "reload_priv" ),
                        ( 8, "shutdown_priv" ),
                        ( 9, "process_priv" ),
                        ( 10, "file_priv" ),
                        ( 11, "grant_priv" ),
                        ( 12, "references_priv" ),
                        ( 13, "index_priv" ),
                        ( 14, "alter_priv" ),
                        ( 15, "show_db_priv" ),
                        ( 16, "super_priv" ),
                        ( 17, "create_tmp_table_priv" ),
                        ( 18, "lock_tables_priv" ),
                        ( 19, "execute_priv" ),
                        ( 20, "repl_slave_priv" ),
                        ( 21, "repl_client_priv" ),
                        ( 22, "create_view_priv" ),
                        ( 23, "show_view_priv" ),
                        ( 24, "create_routine_priv" ),
                        ( 25, "alter_routine_priv" ),
                        ( 26, "create_user_priv" ),
                     )

        pgsqlPrivs = (
                        ( 1, "createdb" ),
                        ( 2, "super" ),
                        ( 3, "catupd" ),
                     )

        firebirdPrivs = {
                         "S": "SELECT",
                         "I": "INSERT",
                         "U": "UPDATE",
                         "D": "DELETE",
                         "R": "REFERENCES",
                         "E": "EXECUTE"
                     }

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                query     = rootQuery.inband.query2
                condition = rootQuery.inband.condition2
            elif Backend.getIdentifiedDbms() == DBMS.ORACLE and query2:
                query     = rootQuery.inband.query2
                condition = rootQuery.inband.condition2
            else:
                query     = rootQuery.inband.query
                condition = rootQuery.inband.condition

            if conf.user:
                users = conf.user.split(",")
                query += " WHERE "
                # NOTE: I assume that the user provided is not in
                # MySQL >= 5.0 syntax 'user'@'host'
                if Backend.getIdentifiedDbms() == DBMS.MYSQL and kb.data.has_information_schema:
                    queryUser = "%" + conf.user + "%"
                    query += " OR ".join("%s LIKE '%s'" % (condition, "%" + user + "%") for user in users)
                else:
                    query += " OR ".join("%s = '%s'" % (condition, user) for user in users)

            values = inject.getValue(query, blind=False)

            if not values and Backend.getIdentifiedDbms() == DBMS.ORACLE and not query2:
                infoMsg = "trying with table USER_SYS_PRIVS"
                logger.info(infoMsg)

                return self.getPrivileges(query2=True)

            if values:
                for value in values:
                    user       = None
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
                            if Backend.getIdentifiedDbms() == DBMS.PGSQL and getUnicode(privilege).isdigit():
                                for position, pgsqlPriv in pgsqlPrivs:
                                    if count == position and int(privilege) == 1:
                                        privileges.add(pgsqlPriv)

                            # In MySQL >= 5.0 and Oracle we get the list
                            # of privileges as string
                            elif Backend.getIdentifiedDbms() == DBMS.ORACLE or ( Backend.getIdentifiedDbms() == DBMS.MYSQL and kb.data.has_information_schema ):
                                privileges.add(privilege)

                            # In MySQL < 5.0 we get Y if the privilege is 
                            # True, N otherwise
                            elif Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                                for position, mysqlPriv in mysqlPrivs:
                                    if count == position and privilege.upper() == "Y":
                                        privileges.add(mysqlPriv)

                    if self.__isAdminFromPrivileges(privileges):
                        areAdmins.add(user)

                    if kb.data.cachedUsersPrivileges.has_key(user):
                        kb.data.cachedUsersPrivileges[user].extend(privileges)
                    else:
                        kb.data.cachedUsersPrivileges[user] = list(privileges)

        if not kb.data.cachedUsersPrivileges and not conf.direct:
            conditionChar = "="

            if conf.user:
                if Backend.getIdentifiedDbms() == DBMS.MYSQL and kb.data.has_information_schema:
                    conditionChar = " LIKE "

                    if "," in conf.user:
                        users = set()
                        for user in conf.user.split(","):
                            users.add("%" + user + "%")
                    else:
                        parsedUser = re.search("[\047]*(.*?)[\047]*\@", conf.user)

                        if parsedUser:
                            conf.user = parsedUser.groups()[0]

                        users = [ "%" + conf.user + "%" ]
                else:
                    users = conf.user.split(",")
            else:
                if not len(kb.data.cachedUsers):
                    users = self.getUsers()
                else:
                    users = kb.data.cachedUsers

            retrievedUsers = set()

            for user in users:
                unescapedUser = None

                if Backend.getIdentifiedDbms() == DBMS.MYSQL and kb.data.has_information_schema:
                    unescapedUser = unescaper.unescape(user, quote=False)

                if not user or user in retrievedUsers:
                    continue

                infoMsg  = "fetching number of privileges "
                infoMsg += "for user '%s'" % user
                logger.info(infoMsg)

                if unescapedUser:
                    queryUser = unescapedUser
                else:
                    queryUser = user

                if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                    query = rootQuery.blind.count2 % queryUser
                elif Backend.getIdentifiedDbms() == DBMS.MYSQL and kb.data.has_information_schema:
                    query = rootQuery.blind.count % (conditionChar, queryUser)
                elif Backend.getIdentifiedDbms() == DBMS.ORACLE and query2:
                    query = rootQuery.blind.count2 % queryUser
                else:
                    query = rootQuery.blind.count % queryUser
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    if not (isinstance(count, basestring) and count.isdigit()) and Backend.getIdentifiedDbms() == DBMS.ORACLE and not query2:
                        infoMsg = "trying with table USER_SYS_PRIVS"
                        logger.info(infoMsg)

                        return self.getPrivileges(query2=True)

                    warnMsg  = "unable to retrieve the number of "
                    warnMsg += "privileges for user '%s'" % user
                    logger.warn(warnMsg)
                    continue

                infoMsg = "fetching privileges for user '%s'" % user
                logger.info(infoMsg)

                privileges = set()

                if Backend.getIdentifiedDbms() == DBMS.ORACLE:
                    plusOne = True
                else:
                    plusOne = False
                indexRange = getRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2 % (queryUser, index)
                    elif Backend.getIdentifiedDbms() == DBMS.MYSQL and kb.data.has_information_schema:
                        query = rootQuery.blind.query % (conditionChar, queryUser, index)
                    elif Backend.getIdentifiedDbms() == DBMS.ORACLE and query2:
                        query = rootQuery.blind.query2 % (queryUser, index)
                    elif Backend.getIdentifiedDbms() == DBMS.FIREBIRD:
                        query = rootQuery.blind.query % (index, queryUser)
                    else:
                        query = rootQuery.blind.query % (queryUser, index)
                    privilege = inject.getValue(query, inband=False, error=False)

                    # In PostgreSQL we get 1 if the privilege is True,
                    # 0 otherwise
                    if Backend.getIdentifiedDbms() == DBMS.PGSQL and ", " in privilege:
                        privilege = privilege.replace(", ", ",")
                        privs = privilege.split(",")
                        i = 1

                        for priv in privs:
                            if priv.isdigit() and int(priv) == 1:
                                for position, pgsqlPriv in pgsqlPrivs:
                                    if position == i:
                                        privileges.add(pgsqlPriv)

                            i += 1

                    # In MySQL >= 5.0 and Oracle we get the list
                    # of privileges as string
                    elif Backend.getIdentifiedDbms() == DBMS.ORACLE or ( Backend.getIdentifiedDbms() == DBMS.MYSQL and kb.data.has_information_schema ):
                        privileges.add(privilege)

                    # In MySQL < 5.0 we get Y if the privilege is 
                    # True, N otherwise
                    elif Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                        privilege = privilege.replace(", ", ",")
                        privs = privilege.split(",")
                        i = 1

                        for priv in privs:
                            if priv.upper() == "Y":
                                for position, mysqlPriv in mysqlPrivs:
                                    if position == i:
                                        privileges.add(mysqlPriv)

                            i += 1

                    # In Firebird we get one letter for each privilege
                    elif Backend.getIdentifiedDbms() == DBMS.FIREBIRD:
                        privileges.add(firebirdPrivs[privilege.strip()])

                    if self.__isAdminFromPrivileges(privileges):
                        areAdmins.add(user)

                    # In MySQL < 5.0 we break the cycle after the first
                    # time we get the user's privileges otherwise we
                    # duplicate the same query
                    if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                        break

                if privileges:
                    kb.data.cachedUsersPrivileges[user] = list(privileges)
                else:
                    warnMsg  = "unable to retrieve the privileges "
                    warnMsg += "for user '%s'" % user
                    logger.warn(warnMsg)

                retrievedUsers.add(user)

        if not kb.data.cachedUsersPrivileges:
            errMsg  = "unable to retrieve the privileges "
            errMsg += "for the database users"
            raise sqlmapNoneDataException, errMsg

        return ( kb.data.cachedUsersPrivileges, areAdmins )

    def getRoles(self, query2=False):
        warnMsg  = "on %s the concept of roles does not " % Backend.getIdentifiedDbms()
        warnMsg += "exist. sqlmap will enumerate privileges instead"
        logger.warn(warnMsg)

        return self.getPrivileges(query2)

    def getDbs(self):
        if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
            warnMsg  = "information_schema not available, "
            warnMsg += "back-end DBMS is MySQL < 5. database "
            warnMsg += "names will be fetched from 'mysql' database"
            logger.warn(warnMsg)

        infoMsg = "fetching database names"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].dbs

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query
            value = inject.getValue(query, blind=False)

            if value:
                kb.data.cachedDbs = arrayizeValue(value)

        if not kb.data.cachedDbs and not conf.direct:
            infoMsg = "fetching number of databases"
            logger.info(infoMsg)

            if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                query = rootQuery.blind.count2
            else:
                query = rootQuery.blind.count
            count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

            if not isNumPosStrValue(count):
                errMsg = "unable to retrieve the number of databases"
                raise sqlmapNoneDataException, errMsg

            indexRange = getRange(count)

            for index in indexRange:
                if Backend.getIdentifiedDbms() == DBMS.SYBASE:
                    query = rootQuery.blind.query % (kb.data.cachedDbs[-1] if kb.data.cachedDbs else " ")
                elif Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                    query = rootQuery.blind.query2 % index
                else:
                    query = rootQuery.blind.query % index
                db = inject.getValue(query, inband=False, error=False)

                if db:
                    kb.data.cachedDbs.append(db)

        if not kb.data.cachedDbs:
            errMsg = "unable to retrieve the database names"
            raise sqlmapNoneDataException, errMsg

        return kb.data.cachedDbs

    def getTables(self, bruteForce=None):
        self.forceDbmsEnum()

        if bruteForce is None:
            if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                errMsg  = "information_schema not available, "
                errMsg += "back-end DBMS is MySQL < 5.0"
                logger.error(errMsg)
                bruteForce = True

            elif Backend.getIdentifiedDbms() == DBMS.ACCESS:
                try:
                    tables = self.getTables(False)
                except sqlmapNoneDataException:
                    tables = None

                if not tables:
                    errMsg  = "cannot retrieve table names, "
                    errMsg += "back-end DBMS is Access"
                    logger.error(errMsg)
                    bruteForce = True
                else:
                    return tables

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

            message = "do you want to use common table existance check? [Y/n/q]"
            test = readInput(message, default="Y")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException
            else:
                return tableExists(paths.COMMON_TABLES)

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
            query = rootQuery.inband.query
            condition = rootQuery.inband.condition if 'condition' in rootQuery.inband else None

            if condition:
                if conf.db and Backend.getIdentifiedDbms() != DBMS.SQLITE:
                    if "," in conf.db:
                        dbs = conf.db.split(",")
                        query += " WHERE "
                        query += " OR ".join("%s = '%s'" % (condition, db) for db in dbs)
                    else:
                        query += " WHERE %s='%s'" % (condition, conf.db)
                elif conf.excludeSysDbs:
                    query += " WHERE "
                    query += " AND ".join("%s != '%s'" % (condition, db) for db in self.excludeDbsList)
                    infoMsg = "skipping system databases '%s'" % ", ".join(db for db in self.excludeDbsList)
                    logger.info(infoMsg)

            if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                query = safeStringFormat(query, conf.db)
            value = inject.getValue(query, blind=False)

            value = filter(lambda x: x, value)

            if value:
                if Backend.getIdentifiedDbms() == DBMS.SQLITE:
                    if isinstance(value, basestring):
                        value = [[ DBMS.SQLITE, value ]]
                    elif isinstance(value, (list, tuple, set)):
                        newValue = []

                        for v in value:
                            newValue.append([ DBMS.SQLITE, v])

                        value = newValue

                for db, table in value:
                    if not kb.data.cachedTables.has_key(db):
                        kb.data.cachedTables[db] = [table]
                    else:
                        kb.data.cachedTables[db].append(table)

        if not kb.data.cachedTables and not conf.direct:
            for db in dbs:
                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % db
                    logger.info(infoMsg)

                    continue

                infoMsg  = "fetching number of tables for "
                infoMsg += "database '%s'" % db
                logger.info(infoMsg)

                if Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.FIREBIRD, DBMS.MAXDB, DBMS.ACCESS):
                    query = rootQuery.blind.count
                else:
                    query = rootQuery.blind.count % db
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    warnMsg  = "unable to retrieve the number of "
                    warnMsg += "tables for database '%s'" % db
                    logger.warn(warnMsg)
                    continue

                tables = []

                if Backend.getIdentifiedDbms() in ( DBMS.MSSQL, DBMS.ORACLE ):
                    plusOne = True
                else:
                    plusOne = False
                indexRange = getRange(count, plusOne=plusOne)

                for index in indexRange:
                    if Backend.getIdentifiedDbms() == DBMS.SYBASE:
                        query = rootQuery.blind.query % (db, (kb.data.cachedTables[-1] if kb.data.cachedTables else " "))
                    elif Backend.getIdentifiedDbms() in (DBMS.MAXDB, DBMS.ACCESS):
                        query = rootQuery.blind.query % (kb.data.cachedTables[-1] if kb.data.cachedTables else " ")
                    elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.FIREBIRD):
                        query = rootQuery.blind.query % index
                    else:
                        query = rootQuery.blind.query % (db, index)
                    table = inject.getValue(query, inband=False, error=False)
                    tables.append(table)
                    kb.hintValue = table

                if tables:
                    kb.data.cachedTables[db] = tables
                else:
                    warnMsg  = "unable to retrieve the tables "
                    warnMsg += "for database '%s'" % db
                    logger.warn(warnMsg)

        if not kb.data.cachedTables:
            errMsg = "unable to retrieve the tables for any database"
            raise sqlmapNoneDataException, errMsg

        return kb.data.cachedTables

    def getColumns(self, onlyColNames=False):
        bruteForce = False

        if not conf.tbl:
            errMsg = "missing table parameter"
            raise sqlmapMissingMandatoryOptionException, errMsg

        if "." in conf.tbl:
            conf.db, conf.tbl = conf.tbl.split(".")

        self.forceDbmsEnum()

        if not conf.db:
            warnMsg  = "missing database parameter, sqlmap is going to "
            warnMsg += "use the current database to enumerate table "
            warnMsg += "'%s' columns" % conf.tbl
            logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

        if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            logger.error(errMsg)
            bruteForce = True

        elif Backend.getIdentifiedDbms() == DBMS.ACCESS:
            errMsg  = "cannot retrieve column names, "
            errMsg += "back-end DBMS is Access"
            logger.error(errMsg)
            bruteForce = True

        if bruteForce:
            resumeAvailable = False

            for db, table, colName, colType in kb.brute.columns:
                if db == conf.db and table == conf.tbl:
                    resumeAvailable = True
                    break

            if resumeAvailable:
                columns = {}
                for db, table, colName, colType in kb.brute.columns:
                    if db == conf.db and table == conf.tbl:
                        columns[colName] = colType

                kb.data.cachedColumns[conf.db] = {conf.tbl: columns}

                return kb.data.cachedColumns

            message = "do you want to use common columns existance check? [Y/n/q]"
            test = readInput(message, default="Y")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException
            else:
                return columnExists(paths.COMMON_COLUMNS)

        firebirdTypes = {
                            "261":"BLOB",
                            "14":"CHAR",
                            "40":"CSTRING",
                            "11":"D_FLOAT",
                            "27":"DOUBLE",
                            "10":"FLOAT",
                            "16":"INT64",
                            "8":"INTEGER",
                            "9":"QUAD",
                            "7":"SMALLINT",
                            "12":"DATE",
                            "13":"TIME",
                            "35":"TIMESTAMP",
                            "37":"VARCHAR"
                        }

        rootQuery = queries[Backend.getIdentifiedDbms()].columns
        condition = rootQuery.blind.condition if 'condition' in rootQuery.blind else None

        infoMsg = "fetching columns "

        if conf.col:
            if Backend.getIdentifiedDbms() == DBMS.ORACLE:
                conf.col = conf.col.upper()
            colList = conf.col.split(",")
            condQuery = " AND (" + " OR ".join("%s LIKE '%s'" % (condition, "%" + col + "%") for col in colList) + ")"
            infoMsg += "like '%s' " % ", ".join(col for col in colList)
        else:
            condQuery = ""

        infoMsg += "for table '%s' " % conf.tbl
        infoMsg += "on database '%s'" % conf.db
        logger.info(infoMsg)

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                query = rootQuery.inband.query % (conf.tbl, conf.db)
                query += condQuery
            elif Backend.getIdentifiedDbms() == DBMS.ORACLE:
                query = rootQuery.inband.query % conf.tbl.upper()
                query += condQuery
            elif Backend.getIdentifiedDbms() == DBMS.MSSQL:
                query = rootQuery.inband.query % (conf.db, conf.db,
                                                        conf.db, conf.db,
                                                        conf.db, conf.db,
                                                        conf.db, conf.tbl)
                query += condQuery.replace("[DB]", conf.db)
            elif Backend.getIdentifiedDbms() == DBMS.SQLITE:
                query = rootQuery.inband.query % conf.tbl

            value = inject.getValue(query, blind=False)

            if Backend.getIdentifiedDbms() == DBMS.SQLITE:
                parseSqliteTableSchema(value)
            elif value:
                table = {}
                columns = {}

                for columnData in value:
                    name = columnData[0]

                    if len(columnData) == 1:
                        columns[name] = ""
                    else:
                        columns[name] = columnData[1]

                table[conf.tbl] = columns
                kb.data.cachedColumns[conf.db] = table

        if not kb.data.cachedColumns and not conf.direct:
            infoMsg  = "fetching number of columns "
            infoMsg += "for table '%s'" % conf.tbl
            infoMsg += " on database '%s'" % conf.db
            logger.info(infoMsg)

            if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                query = rootQuery.blind.count % (conf.tbl, conf.db)
                query += condQuery
            elif Backend.getIdentifiedDbms() == DBMS.ORACLE:
                query = rootQuery.blind.count % conf.tbl.upper()
                query += condQuery
            elif Backend.getIdentifiedDbms() == DBMS.MSSQL:
                query = rootQuery.blind.count % (conf.db, conf.db, conf.tbl)
                query += condQuery.replace("[DB]", conf.db)
            elif Backend.getIdentifiedDbms() == DBMS.FIREBIRD:
                query = rootQuery.blind.count % (conf.tbl)
                query += condQuery
            elif Backend.getIdentifiedDbms() == DBMS.SQLITE:
                query = rootQuery.blind.query % conf.tbl
                value = inject.getValue(query, inband=False, error=False)

                parseSqliteTableSchema(value)

                return kb.data.cachedColumns

            count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

            if not isNumPosStrValue(count):
                errMsg  = "unable to retrieve the number of columns "
                errMsg += "for table '%s' " % conf.tbl
                errMsg += "on database '%s'" % conf.db
                raise sqlmapNoneDataException, errMsg

            table   = {}
            columns = {}

            indexRange = getRange(count)

            for index in indexRange:
                if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                    query = rootQuery.blind.query % (conf.tbl, conf.db)
                    query += condQuery
                    field = None
                elif Backend.getIdentifiedDbms() == DBMS.ORACLE:
                    query = rootQuery.blind.query % (conf.tbl.upper())
                    query += condQuery
                    field = None
                elif Backend.getIdentifiedDbms() == DBMS.MSSQL:
                    query = rootQuery.blind.query % (conf.db, conf.db,
                                                           conf.db, conf.db,
                                                           conf.db, conf.db,
                                                           conf.tbl)
                    query += condQuery.replace("[DB]", conf.db)
                    field = condition.replace("[DB]", conf.db)
                elif Backend.getIdentifiedDbms() == DBMS.FIREBIRD:
                    query = rootQuery.blind.query % (conf.tbl)
                    query += condQuery
                    field = None

                query = agent.limitQuery(index, query, field)
                column = inject.getValue(query, inband=False, error=False)

                if not onlyColNames:
                    if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                        query = rootQuery.blind.query2 % (conf.tbl, column, conf.db)
                    elif Backend.getIdentifiedDbms() == DBMS.ORACLE:
                        query = rootQuery.blind.query2 % (conf.tbl.upper(), column)
                    elif Backend.getIdentifiedDbms() == DBMS.MSSQL:
                        query = rootQuery.blind.query2 % (conf.db, conf.db, conf.db,
                                                                conf.db, column, conf.db,
                                                                conf.db, conf.db, conf.tbl)
                    elif Backend.getIdentifiedDbms() == DBMS.FIREBIRD:
                        query = rootQuery.blind.query2 % (conf.tbl, column)

                    colType = inject.getValue(query, inband=False, error=False)

                    if Backend.getIdentifiedDbms() == DBMS.FIREBIRD:
                        colType = firebirdTypes[colType] if colType in firebirdTypes else colType

                    columns[column] = colType
                else:
                    columns[column] = None

            if columns:
                table[conf.tbl] = columns
                kb.data.cachedColumns[conf.db] = table

        if not kb.data.cachedColumns:
            errMsg  = "unable to retrieve the columns "
            errMsg += "for table '%s' " % conf.tbl
            errMsg += "on database '%s'" % conf.db
            raise sqlmapNoneDataException, errMsg

        return kb.data.cachedColumns

    def dumpTable(self):
        if not conf.tbl and not conf.col:
            errMsg = "missing table parameter"
            raise sqlmapMissingMandatoryOptionException, errMsg

        if conf.col and not conf.tbl:
            warnMsg = "missing table parameter. You only provided "
            warnMsg += "column(s). sqlmap will search for all databases' "
            warnMsg += "tables containing the provided column(s)"
            logger.warn(warnMsg)

            self.searchColumn()
            return

        if "." in conf.tbl:
            conf.db, conf.tbl = conf.tbl.split(".")

        self.forceDbmsEnum()

        if not conf.db:
            warnMsg  = "missing database parameter, sqlmap is going to "
            warnMsg += "use the current database to dump table "
            warnMsg += "'%s' entries" % conf.tbl
            logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

        rootQuery = queries[Backend.getIdentifiedDbms()].dump_table

        if Backend.getIdentifiedDbms() == DBMS.MYSQL:
            if '-' in conf.tbl:
                conf.tbl = "`%s`" % conf.tbl
            if '-' in conf.db:
                conf.db = "`%s`" % conf.db

        if conf.col:
            colList = conf.col.split(",")
            kb.data.cachedColumns[conf.db] = {}
            kb.data.cachedColumns[conf.db][conf.tbl] = {}

            for column in colList:
                kb.data.cachedColumns[conf.db][conf.tbl][column] = None

        elif not kb.data.cachedColumns:
            kb.data.cachedColumns = self.getColumns(onlyColNames=True)

        if conf.col:
            colList = conf.col.split(",")
        elif kb.data.cachedColumns and conf.db in kb.data.cachedColumns and conf.tbl in kb.data.cachedColumns[conf.db]:
            colList = kb.data.cachedColumns[conf.db][conf.tbl].keys()
        else:
            errMsg  = "missing column names, "
            errMsg += "can't dump table"
            raise sqlmapNoneDataException, errMsg

        if colList in ([None], ['None']):
            warnMsg = "unable to retrieve column names"
            logger.warn(warnMsg)
            return None

        colString = ", ".join(column for column in colList)

        infoMsg = "fetching"
        if conf.col:
            infoMsg += " columns '%s'" % colString
        infoMsg += " entries for table '%s'" % conf.tbl
        infoMsg += " on database '%s'" % conf.db
        logger.info(infoMsg)

        entriesCount = 0

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            entries = []

            if Backend.getIdentifiedDbms() == DBMS.MYSQL and isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) and conf.groupConcat:
                randStr, randStr2 = randomStr(), randomStr()
                filterFunction = "REPLACE(REPLACE(IFNULL(%s, ' '),'%s','%s'),'%s','%s')"\
                  % ('%s', CONCAT_VALUE_DELIMITER, randStr, CONCAT_ROW_DELIMITER, randStr2)
                concats = ",".join(map(lambda x: "CONCAT(%s, '|')" % (filterFunction % x), colList[:-1]))
                concats += ",%s" % (filterFunction % colList[-1])
                query = "SELECT GROUP_CONCAT(%s) FROM %s.%s" % (concats, conf.db, conf.tbl)
                value = inject.getValue(query, blind=False)
                if isinstance(value, basestring):
                    for line in value.split(CONCAT_ROW_DELIMITER):
                        row = line.split(CONCAT_VALUE_DELIMITER)
                        row = filter(lambda x: x.replace(randStr, CONCAT_VALUE_DELIMITER).replace(randStr2, CONCAT_ROW_DELIMITER), row)
                        entries.append(row)

            if Backend.getIdentifiedDbms() == DBMS.ORACLE:
                query = rootQuery.inband.query % (colString, conf.tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), conf.tbl.upper())))
            elif Backend.getIdentifiedDbms() == DBMS.SQLITE:
                query = rootQuery.inband.query % (colString, conf.tbl)
            else:
                query = rootQuery.inband.query % (colString, conf.db, conf.tbl)

            if not (Backend.getIdentifiedDbms() == DBMS.MYSQL and entries):
                entries = inject.getValue(query, blind=False, dump=True)

            if entries:
                if isinstance(entries, basestring):
                    entries = [ entries ]

                entriesCount = len(entries)
                index        = 0

                for column in colList:
                    colLen = len(column)

                    if not kb.data.dumpedTable.has_key(column):
                        kb.data.dumpedTable[column] = { "length": 0, "values": [] }

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

        if not kb.data.dumpedTable and not conf.direct:
            infoMsg = "fetching number of "
            if conf.col:
                infoMsg += "columns '%s' " % colString
            infoMsg += "entries for table '%s' " % conf.tbl
            infoMsg += "on database '%s'" % conf.db
            logger.info(infoMsg)

            if Backend.getIdentifiedDbms() == DBMS.ORACLE:
                query = rootQuery.blind.count % (conf.tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), conf.tbl.upper())))
            elif Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
                query = rootQuery.blind.count % conf.tbl
            else:
                query = rootQuery.blind.count % (conf.db, conf.tbl)
            count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

            if not isNumPosStrValue(count):
                warnMsg = "unable to retrieve the number of "
                if conf.col:
                    warnMsg += "columns '%s' " % colString
                warnMsg += "entries for table '%s' " % conf.tbl
                warnMsg += "on database '%s'" % conf.db

                logger.warn(warnMsg)

                return None

            lengths = {}
            entries = {}

            if Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.MSSQL, DBMS.SYBASE):
                plusOne = True
            else:
                plusOne = False
            indexRange = getRange(count, dump=True, plusOne=plusOne)

            try:
                if Backend.getIdentifiedDbms() == DBMS.ACCESS:
                    validColumnList = False
                    validPivotValue = False

                    for column in colList:
                        infoMsg = "fetching number of distinct "
                        infoMsg += "values for column '%s'" % column
                        logger.info(infoMsg)

                        query = rootQuery.blind.count2 % (column, conf.tbl)
                        value = inject.getValue(query, inband=False, error=False)

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
                        warnMsg += " all rows can't be retrieved."
                        logger.warn(warnMsg)

                    pivotValue = " "
                    breakRetrieval = False

                    for index in indexRange:
                        if breakRetrieval:
                            break

                        for column in colList:
                            if column not in lengths:
                                lengths[column] = 0

                            if column not in entries:
                                entries[column] = []

                            if column == colList[0]:
                                # Correction for pivotValues with unrecognized chars
                                if pivotValue and '?' in pivotValue and pivotValue[0]!='?':
                                    pivotValue = pivotValue.split('?')[0]
                                    pivotValue = pivotValue[:-1] + chr(ord(pivotValue[-1]) + 1)
                                query = rootQuery.blind.query % (column, conf.tbl, column, pivotValue)
                            else:
                                query = rootQuery.blind.query2 % (column, conf.tbl, colList[0], pivotValue)

                            value = inject.getValue(query, inband=False, error=False)

                            if column == colList[0]:
                                if not value:
                                    breakRetrieval = True
                                    break
                                else:
                                    pivotValue = value

                            lengths[column] = max(lengths[column], len(value) if value else 0)
                            entries[column].append(value)
                else:
                    for index in indexRange:
                        for column in colList:
                            if column not in lengths:
                                lengths[column] = 0

                            if column not in entries:
                                entries[column] = []

                            if Backend.getIdentifiedDbms() in ( DBMS.MYSQL, DBMS.PGSQL ):
                                query = rootQuery.blind.query % (column, conf.db,
                                                                       conf.tbl, index)
                            elif Backend.getIdentifiedDbms() == DBMS.ORACLE:
                                query = rootQuery.blind.query % (column, column,
                                                                       conf.tbl.upper() if not conf.db else ("%s.%s" % (conf.db.upper(), conf.tbl.upper())),
                                                                       index)
                            elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                                query = rootQuery.blind.query % (column, index, conf.db,
                                                                       conf.tbl, colList[0],
                                                                       colList[0], colList[0])

                            elif Backend.getIdentifiedDbms() == DBMS.SQLITE:
                                query = rootQuery.blind.query % (column, conf.tbl, index)

                            elif Backend.getIdentifiedDbms() == DBMS.FIREBIRD:
                                query = rootQuery.blind.query % (index, column, conf.tbl)

                            value = inject.getValue(query, inband=False, error=False)

                            lengths[column] = max(lengths[column], len(value) if value else 0)
                            entries[column].append(value)
            except KeyboardInterrupt:
                warnMsg = "Ctrl+C detected in dumping phase"
                logger.warn(warnMsg)

            except sqlmapConnectionException, e:
                errMsg = "connection exception detected in dumping phase: "
                errMsg += "'%s'" % e
                logger.critical(errMsg)

            for column, columnEntries in entries.items():
                length = max(lengths[column], len(column))

                kb.data.dumpedTable[column] = { "length": length,
                                                "values": columnEntries }

                entriesCount = len(columnEntries)

        if kb.data.dumpedTable:
            kb.data.dumpedTable["__infos__"] = { "count": entriesCount,
                                                 "table": conf.tbl,
                                                 "db":    conf.db }
        else:
            warnMsg = "unable to retrieve the entries of "
            if conf.col:
                warnMsg += "columns '%s' " % colString
            warnMsg += "for table '%s' " % conf.tbl
            warnMsg += "on database '%s'" % conf.db

            logger.warn(warnMsg)

            return None

        attackDumpedTable()

        return kb.data.dumpedTable

    def dumpAll(self):
        if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            raise sqlmapUnsupportedFeatureException, errMsg

        conf.db              = None
        conf.tbl             = None
        conf.col             = None
        kb.data.cachedDbs    = []
        kb.data.cachedTables = self.getTables()

        if kb.data.cachedTables:
            if isinstance(kb.data.cachedTables, list):
                kb.data.cachedTables = { None : kb.data.cachedTables }

            for db, tables in kb.data.cachedTables.items():
                conf.db = db

                for table in tables:
                    conf.tbl = table
                    kb.data.cachedColumns = {}
                    kb.data.dumpedTable = {}

                    data = self.dumpTable()

                    if data:
                        conf.dumper.dbTableValues(data)

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
                conf.col = ",".join(column for column in columns)
                kb.data.cachedColumns = {}
                kb.data.dumpedTable = {}

                data = self.dumpTable()

                if data:
                    conf.dumper.dbTableValues(data)

    def searchDb(self):
        foundDbs = []
        rootQuery = queries[Backend.getIdentifiedDbms()].search_db
        dbList = conf.db.split(",")

        if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
            dbCond = rootQuery.inband.condition2
        else:
            dbCond = rootQuery.inband.condition

        dbConsider, dbCondParam = self.likeOrExact("database")

        for db in dbList:
            infoMsg = "searching database"
            if dbConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % db
            logger.info(infoMsg)

            if conf.excludeSysDbs:
                exclDbsQuery = "".join(" AND '%s' != %s" % (db, dbCond) for db in self.excludeDbsList)
                infoMsg = "skipping system databases '%s'" % ", ".join(db for db in self.excludeDbsList)
                logger.info(infoMsg)
            else:
                exclDbsQuery = ""

            dbQuery = "%s%s" % (dbCond, dbCondParam)
            dbQuery = dbQuery % db

            if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
                if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                    query = rootQuery.inband.query2
                else:
                    query = rootQuery.inband.query
                query += dbQuery
                query += exclDbsQuery
                values = inject.getValue(query, blind=False)

                if values:
                    if isinstance(values, basestring):
                        values = [ values ]

                    for value in values:
                        foundDbs.append(value)
            else:
                infoMsg = "fetching number of databases"
                if dbConsider == "1":
                    infoMsg += "s like"
                infoMsg += " '%s'" % db
                logger.info(infoMsg)

                if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                    query = rootQuery.blind.count2
                else:
                    query = rootQuery.blind.count
                query += dbQuery
                query += exclDbsQuery
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    warnMsg  = "no database"
                    if dbConsider == "1":
                        warnMsg += "s like"
                    warnMsg += " '%s' found" % db
                    logger.warn(warnMsg)

                    continue

                indexRange = getRange(count)

                for index in indexRange:
                    if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2
                    else:
                        query = rootQuery.blind.query
                    query += dbQuery
                    query += exclDbsQuery
                    query = agent.limitQuery(index, query, dbCond)

                    foundDbs.append(inject.getValue(query, inband=False, error=False))

        return foundDbs

    def searchTable(self):
        bruteForce = False

        if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            bruteForce = True

        elif Backend.getIdentifiedDbms() == DBMS.ACCESS:
            errMsg  = "cannot retrieve table names, "
            errMsg += "back-end DBMS is Access"
            logger.error(errMsg)
            bruteForce = True

        if bruteForce:
            message = "do you want to use common table existance check? [Y/n/q]"
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
            if Backend.getIdentifiedDbms() == DBMS.ORACLE:
                tbl = tbl.upper()

            infoMsg = "searching table"
            if tblConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % tbl
            logger.info(infoMsg)

            if conf.excludeSysDbs:
                exclDbsQuery = "".join(" AND '%s' != %s" % (db, dbCond) for db in self.excludeDbsList)
                infoMsg = "skipping system databases '%s'" % ", ".join(db for db in self.excludeDbsList)
                logger.info(infoMsg)
            else:
                exclDbsQuery = ""

            tblQuery = "%s%s" % (tblCond, tblCondParam)
            tblQuery = tblQuery % tbl

            if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
                query = rootQuery.inband.query
                query += tblQuery
                query += exclDbsQuery
                values = inject.getValue(query, blind=False)

                if values:
                    if isinstance(values, basestring):
                        values = [ values ]

                    for foundDb, foundTbl in values:
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
                infoMsg += " '%s'" % tbl
                logger.info(infoMsg)

                query = rootQuery.blind.count
                query += tblQuery
                query += exclDbsQuery
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    warnMsg  = "no databases have table"
                    if tblConsider == "1":
                        warnMsg += "s like"
                    warnMsg += " '%s'" % tbl
                    logger.warn(warnMsg)

                    continue

                indexRange = getRange(count)

                for index in indexRange:
                    query = rootQuery.blind.query
                    query += tblQuery
                    query += exclDbsQuery
                    query = agent.limitQuery(index, query)
                    foundDb = inject.getValue(query, inband=False, error=False)

                    if foundDb not in foundTbls:
                        foundTbls[foundDb] = []

                    if tblConsider == "2":
                        foundTbls[foundDb].append(tbl)

                if tblConsider == "2":
                    continue

                for db in foundTbls.keys():
                    infoMsg = "fetching number of table"
                    if tblConsider == "1":
                        infoMsg += "s like"
                    infoMsg += " '%s' in database '%s'" % (tbl, db)
                    logger.info(infoMsg)

                    query = rootQuery.blind.count2
                    query = query % db
                    query += " AND %s" % tblQuery
                    count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                    if not isNumPosStrValue(count):
                        warnMsg = "no table"
                        if tblConsider == "1":
                            warnMsg += "s like"
                        warnMsg += " '%s' " % tbl
                        warnMsg += "in database '%s'" % db
                        logger.warn(warnMsg)

                        continue

                    indexRange = getRange(count)

                    for index in indexRange:
                        query = rootQuery.blind.query2
                        query = query % db
                        query += " AND %s" % tblQuery
                        query = agent.limitQuery(index, query)
                        foundTbl = inject.getValue(query, inband=False, error=False)
                        kb.hintValue = foundTbl
                        foundTbls[db].append(foundTbl)

        return foundTbls

    def searchColumn(self):
        bruteForce = False

        if Backend.getIdentifiedDbms() == DBMS.MYSQL and not kb.data.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            bruteForce = True

        elif Backend.getIdentifiedDbms() == DBMS.ACCESS:
            errMsg  = "cannot retrieve column names, "
            errMsg += "back-end DBMS is Access"
            logger.error(errMsg)
            bruteForce = True

        if bruteForce:
            message = "do you want to use common columns existance check? [Y/n/q]"
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
            infoMsg = "searching column"
            if colConsider == "1":
                infoMsg += "s like"
            infoMsg += " '%s'" % column
            logger.info(infoMsg)

            foundCols[column] = {}

            if conf.excludeSysDbs:
                exclDbsQuery = "".join(" AND '%s' != %s" % (db, dbCond) for db in self.excludeDbsList)
                infoMsg = "skipping system databases '%s'" % ", ".join(db for db in self.excludeDbsList)
                logger.info(infoMsg)
            else:
                exclDbsQuery = ""

            colQuery = "%s%s" % (colCond, colCondParam)
            colQuery = colQuery % column

            if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
                query = rootQuery.inband.query
                query += colQuery
                query += exclDbsQuery
                values = inject.getValue(query, blind=False)

                if values:
                    if isinstance(values, basestring):
                        values = [ values ]

                    for foundDb, foundTbl in values:
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

                            self.getColumns(onlyColNames=True)

                            dbs[foundDb][foundTbl].update(kb.data.cachedColumns[foundDb][foundTbl])
                            kb.data.cachedColumns = {}
                        else:
                            dbs[foundDb][foundTbl][column] = None

                        if foundDb in foundCols[column]:
                            foundCols[column][foundDb].append(foundTbl)
                        else:
                            foundCols[column][foundDb] = [ foundTbl ]
            else:
                infoMsg = "fetching number of databases with tables containing column"
                if colConsider == "1":
                    infoMsg += "s like"
                infoMsg += " '%s'" % column
                logger.info(infoMsg)

                query = rootQuery.blind.count
                query += colQuery
                query += exclDbsQuery
                count = inject.getValue(query, inband=False, error=False, expected=EXPECTED.INT, charsetType=2)

                if not isNumPosStrValue(count):
                    warnMsg  = "no databases have tables containing column"
                    if colConsider == "1":
                        warnMsg += "s like"
                    warnMsg += " '%s'" % column
                    logger.warn(warnMsg)

                    continue

                indexRange = getRange(count)

                for index in indexRange:
                    query = rootQuery.blind.query
                    query += colQuery
                    query += exclDbsQuery
                    query = agent.limitQuery(index, query)
                    db = inject.getValue(query, inband=False, error=False)

                    if db not in dbs:
                        dbs[db] = {}

                    if db not in foundCols[column]:
                        foundCols[column][db] = []

                for column, dbData in foundCols.items():
                    colQuery = "%s%s" % (colCond, colCondParam)
                    colQuery = colQuery % column

                    for db in dbData:
                        infoMsg = "fetching number of tables containing column"
                        if colConsider == "1":
                            infoMsg += "s like"
                        infoMsg += " '%s' in database '%s'" % (column, db)
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

    def search(self):
        if conf.db:
            conf.dumper.lister("found databases", self.searchDb())

        if conf.tbl:
            conf.dumper.dbTables(self.searchTable())

        if conf.col:
            self.searchColumn()

        if not conf.db and not conf.tbl and not conf.col:
            errMsg = "missing parameter, provide -D, -T or -C together "
            errMsg += "with --search"
            raise sqlmapMissingMandatoryOptionException, errMsg

    def sqlQuery(self, query):
        output = None
        sqlType = None
        getOutput = None

        for sqlTitle, sqlStatements in SQL_STATEMENTS.items():
            for sqlStatement in sqlStatements:
                if query.lower().startswith(sqlStatement):
                    sqlType = sqlTitle

                    break

        if not self.alwaysRetrieveSqlOutput:
            message = "do you want to retrieve the SQL statement output? "
            message += "[Y/n/a] "
            getOutput = readInput(message, default="Y")

            if getOutput in ("a", "A"):
                self.alwaysRetrieveSqlOutput = True

        if not getOutput or getOutput in ("y", "Y") or self.alwaysRetrieveSqlOutput:
            infoMsg = "fetching %s query output: '%s'" % (sqlType if sqlType is not None else "SQL", query)
            logger.info(infoMsg)

            output = inject.getValue(query, fromUser=True)

            return output
        else:
            if not isTechniqueAvailable(PAYLOAD.TECHNIQUE.STACKED) and not conf.direct:
                warnMsg  = "execution of custom SQL queries is only "
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
        infoMsg  = "calling %s shell. To quit type " % Backend.getIdentifiedDbms()
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
