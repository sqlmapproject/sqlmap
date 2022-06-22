#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import getLimitRange
from lib.core.common import isAdminFromPrivileges
from lib.core.common import isInferenceAvailable
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapNoneDataException
from lib.core.settings import CURRENT_USER
from lib.request import inject
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def getRoles(self, query2=False):
        infoMsg = "fetching database users roles"

        rootQuery = queries[DBMS.ORACLE].roles

        if conf.user == CURRENT_USER:
            infoMsg += " for current user"
            conf.user = self.getCurrentUser()

        logger.info(infoMsg)

        # Set containing the list of DBMS administrators
        areAdmins = set()

        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            if query2:
                query = rootQuery.inband.query2
                condition = rootQuery.inband.condition2
            else:
                query = rootQuery.inband.query
                condition = rootQuery.inband.condition

            if conf.user:
                users = conf.user.split(',')
                query += " WHERE "
                query += " OR ".join("%s = '%s'" % (condition, user) for user in sorted(users))

            values = inject.getValue(query, blind=False, time=False)

            if not values and not query2:
                infoMsg = "trying with table 'USER_ROLE_PRIVS'"
                logger.info(infoMsg)

                return self.getRoles(query2=True)

            if not isNoneValue(values):
                for value in values:
                    user = None
                    roles = set()

                    for count in xrange(0, len(value or [])):
                        # The first column is always the username
                        if count == 0:
                            user = value[count]

                        # The other columns are the roles
                        else:
                            role = value[count]

                            # In Oracle we get the list of roles as string
                            roles.add(role)

                    if user in kb.data.cachedUsersRoles:
                        kb.data.cachedUsersRoles[user] = list(roles.union(kb.data.cachedUsersRoles[user]))
                    else:
                        kb.data.cachedUsersRoles[user] = list(roles)

        if not kb.data.cachedUsersRoles and isInferenceAvailable() and not conf.direct:
            if conf.user:
                users = conf.user.split(',')
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

                infoMsg = "fetching number of roles "
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
                count = inject.getValue(query, union=False, error=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

                if not isNumPosStrValue(count):
                    if count != 0 and not query2:
                        infoMsg = "trying with table 'USER_SYS_PRIVS'"
                        logger.info(infoMsg)

                        return self.getPrivileges(query2=True)

                    warnMsg = "unable to retrieve the number of "
                    warnMsg += "roles for user '%s'" % user
                    logger.warning(warnMsg)
                    continue

                infoMsg = "fetching roles for user '%s'" % user
                logger.info(infoMsg)

                roles = set()

                indexRange = getLimitRange(count, plusOne=True)

                for index in indexRange:
                    if query2:
                        query = rootQuery.blind.query2 % (queryUser, index)
                    else:
                        query = rootQuery.blind.query % (queryUser, index)
                    role = inject.getValue(query, union=False, error=False)

                    # In Oracle we get the list of roles as string
                    roles.add(role)

                if roles:
                    kb.data.cachedUsersRoles[user] = list(roles)
                else:
                    warnMsg = "unable to retrieve the roles "
                    warnMsg += "for user '%s'" % user
                    logger.warning(warnMsg)

                retrievedUsers.add(user)

        if not kb.data.cachedUsersRoles:
            errMsg = "unable to retrieve the roles "
            errMsg += "for the database users"
            raise SqlmapNoneDataException(errMsg)

        for user, privileges in kb.data.cachedUsersRoles.items():
            if isAdminFromPrivileges(privileges):
                areAdmins.add(user)

        return kb.data.cachedUsersRoles, areAdmins
