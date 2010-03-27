#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

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

from lib.core.common import getRange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.exception import sqlmapNoneDataException
from lib.request import inject

from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self, "Oracle")

    def getRoles(self, query2=False):
        infoMsg = "fetching database users roles"

        rootQuery = queries[kb.dbms].roles

        if conf.user == "CU":
            infoMsg += " for current user"
            conf.user = self.getCurrentUser()

        logger.info(infoMsg)

        # Set containing the list of DBMS administrators
        areAdmins = set()

        if kb.unionPosition or conf.direct:
            if query2:
                query     = rootQuery["inband"]["query2"]
                condition = rootQuery["inband"]["condition2"]
            else:
                query     = rootQuery["inband"]["query"]
                condition = rootQuery["inband"]["condition"]

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

        if not kb.data.cachedUsersRoles:
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
                    query = rootQuery["blind"]["count2"] % queryUser
                else:
                    query = rootQuery["blind"]["count"] % queryUser
                count = inject.getValue(query, inband=False, expected="int", charsetType=2)

                if not count.isdigit() or not len(count) or count == "0":
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
                        query = rootQuery["blind"]["query2"] % (queryUser, index)
                    else:
                        query = rootQuery["blind"]["query"] % (queryUser, index)
                    role = inject.getValue(query, inband=False)

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

    def getDbs(self):
        warnMsg = "on Oracle it is not possible to enumerate databases"
        logger.warn(warnMsg)

        return []
