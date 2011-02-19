#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
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
from lib.core.exception import sqlmapUnsupportedFeatureException
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
        condition = rootQuery.blind.condition if 'condition' in rootQuery.blind else None

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
