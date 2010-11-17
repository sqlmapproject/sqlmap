#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import time

from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import getConsoleWidth
from lib.core.common import getFileItems
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import safeStringFormat
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.request.connect import Connect as Request

def tableExists(tableFile):
    tables = getFileItems(tableFile)
    retVal = []
    infoMsg = "checking table existence using items from '%s'" % tableFile
    logger.info(infoMsg)

    pushValue(conf.verbose)
    conf.verbose = 0
    count = 0
    length = len(tables)

    for table in tables:
        if conf.db and '(*)' not in conf.db:
            table = "%s.%s" % (conf.db, table)
        query = agent.prefixQuery("%s" % safeStringFormat("AND EXISTS(SELECT %d FROM %s)", (randomInt(1), table)))
        query = agent.suffixQuery(query)
        result = Request.queryPage(agent.payload(newValue=query))

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
    else:
        for item in retVal:
            if not kb.data.cachedTables.has_key(conf.db):
                kb.data.cachedTables[conf.db] = [item]
            else:
                kb.data.cachedTables[conf.db].append(item)

    return kb.data.cachedTables

def columnExists(columnFile):
    if not conf.tbl:
        errMsg = "missing table parameter"
        raise sqlmapMissingMandatoryOptionException, errMsg

    columns = getFileItems(columnFile)
    if conf.db and '(*)' not in conf.db:
        table = "%s.%s" % (conf.db, conf.tbl)
    else:
        table = conf.tbl

    retVal = []
    infoMsg = "checking column existence using items from '%s'" % columnFile
    logger.info(infoMsg)

    pushValue(conf.verbose)
    conf.verbose = 0
    count = 0
    length = len(columns)

    for column in columns:
        query = agent.prefixQuery("%s" % safeStringFormat("AND EXISTS(SELECT %s FROM %s)", (column, table)))
        query = agent.suffixQuery(query)
        result = Request.queryPage(agent.payload(newValue=query))

        if result:
            infoMsg = "\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), column)
            infoMsg = "%s%s\n" % (infoMsg, " "*(getConsoleWidth()-1-len(infoMsg)))
            dataToStdout(infoMsg, True)
            retVal.append(column)

        count += 1
        status = '%d/%d items (%d%s)' % (count, length, round(100.0*count/length), '%')
        dataToStdout("\r[%s] [INFO] tried: %s" % (time.strftime("%X"), status), True)

    conf.verbose = popValue()

    dataToStdout("\n", True)

    if not retVal:
        warnMsg = "no column found"
        logger.warn(warnMsg)
    else:
        columns = {}

        for column in retVal:
            query = agent.prefixQuery("%s" % safeStringFormat("AND EXISTS(SELECT %s FROM %s WHERE %s>0)", (column, table, column)))
            query = agent.suffixQuery(query)
            result = Request.queryPage(agent.payload(newValue=query))

            if result:
                columns[column] = 'numeric'
            else:
                columns[column] = 'non-numeric'

        kb.data.cachedColumns[conf.db] = {conf.tbl: columns}

    return kb.data.cachedColumns
