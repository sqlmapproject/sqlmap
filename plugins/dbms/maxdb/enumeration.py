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
from lib.core.exception import sqlmapMissingMandatoryOptionException
from plugins.generic.enumeration import Enumeration as GenericEnumeration

class Enumeration(GenericEnumeration):
    def __init__(self):
        GenericEnumeration.__init__(self)

        kb.data.processChar = lambda x: x.replace('_', ' ') if x else x

    def getPasswordHashes(self):
        warnMsg = "on SAP MaxDB it is not possible to enumerate the user password hashes"
        logger.warn(warnMsg)

        return {}

    def searchDb(self):
        warnMsg = "on SAP MaxDB it is not possible to search databases"
        logger.warn(warnMsg)

        return []

    def getColumns(self, onlyColNames=False):
        if not conf.tbl:
            errMsg = "missing table parameter"
            raise sqlmapMissingMandatoryOptionException, errMsg

        if "." in conf.tbl:
            conf.db, conf.tbl = conf.tbl.split(".")

        self.forceDbmsEnum()

        rootQuery = queries[Backend.getIdentifiedDbms()].columns

        infoMsg = "fetching columns "
        infoMsg += "for table '%s' " % conf.tbl
        if conf.db:
            infoMsg += "on schema '%s'" % conf.db
        logger.info(infoMsg)

        randStr = randomStr()
        query = rootQuery.inband.query % (conf.tbl, ("'%s'" % conf.db) if conf.db != "USER" else 'USER')
        retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.columnname' % randStr,'%s.datatype' % randStr,'%s.len' % randStr], blind=True)

        if retVal:
            table = {}
            columns = {}

            for columnname, datatype, length in zip(retVal[0]["%s.columnname" % randStr], retVal[0]["%s.datatype" % randStr], retVal[0]["%s.len" % randStr]):
                columns[columnname] = "%s(%s)" % (datatype, length)

            table[conf.tbl] = columns
            kb.data.cachedColumns[conf.db] = table

        return kb.data.cachedColumns

    def getTables(self, bruteForce=None):
        self.forceDbmsEnum()

        infoMsg = "fetching tables"
        if conf.db:
            infoMsg += " for schema '%s'" % conf.db
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

        for db in dbs:
            randStr = randomStr()
            query = rootQuery.inband.query % (("'%s'" % db) if db != "USER" else 'USER')
            retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.tablename' % randStr], blind=True)

            if retVal:
                for table in retVal[0].values()[0]:
                    if not kb.data.cachedTables.has_key(db):
                        kb.data.cachedTables[db] = [table]
                    else:
                        kb.data.cachedTables[db].append(table)

        return kb.data.cachedTables

    def getDbs(self):
        infoMsg = "fetching database names"
        logger.info(infoMsg)

        rootQuery = queries[Backend.getIdentifiedDbms()].dbs

        randStr = randomStr()
        query = rootQuery.inband.query

        retVal = self.__pivotDumpTable("(%s) AS %s" % (query, randStr), ['%s.schemaname' % randStr], blind=True)

        if retVal:
            kb.data.cachedDbs = retVal[0].values()[0]

        return kb.data.cachedDbs
