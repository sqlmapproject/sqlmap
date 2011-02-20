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
from lib.core.enums import PAYLOAD
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

        kb.data.processChar = lambda x: x.replace('_', ' ') if x else x

    def getDbs(self):
        warnMsg = "on SAP MaxDB it is not possible to enumerate databases"
        logger.warn(warnMsg)

        return []

    def getPasswordHashes(self):
        warnMsg = "on SAP MaxDB it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "on SAP MaxDB it is not possible to search databases"
        logger.warn(warnMsg)

        return []

    def getColumns(self, onlyColNames=False):
        self.forceDbmsEnum()

        rootQuery = queries[Backend.getIdentifiedDbms()].columns
        condition = rootQuery.blind.condition if 'condition' in rootQuery.blind else None

        infoMsg = "fetching columns "
        infoMsg += "for table '%s' " % conf.tbl
        logger.info(infoMsg)

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION) or isTechniqueAvailable(PAYLOAD.TECHNIQUE.ERROR) or conf.direct:
            blinds = [False, True]
        else:
            blinds = [True]

        for blind in blinds:
            randStr = randomStr()
            query = rootQuery.inband.query % conf.tbl
            retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.columnname' % randStr,'%s.datatype' % randStr,'%s.len' % randStr], blind=blind)

            if retVal:
                table = {}
                columns = {}

                for columnname, datatype, length in zip(retVal[0]["%s.columnname" % randStr], retVal[0]["%s.datatype" % randStr], retVal[0]["%s.len" % randStr]):
                    columns[columnname] = "%s(%s)" % (datatype, length)

                table[conf.tbl] = columns
                kb.data.cachedColumns[conf.db] = table

                break

        return kb.data.cachedColumns
