#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import time

from lib.core.common import clearConsoleLine,  dataToStdout,  filterListValue,  getFileItems,  Backend, \
    getPageWordSet,  hashDBWrite, randomInt, randomStr, safeStringFormat, safeSQLIdentificatorNaming
from lib.core.data import conf, kb, logger
from lib.core.enums import DBMS, HASHDB_KEYS
from lib.core.exception import sqlmapDataException, sqlmapMissingMandatoryOptionException
from lib.core.settings import METADB_SUFFIX, BRUTE_COLUMN_EXISTS_TEMPLATE, BRUTE_TABLE_EXISTS_TEMPLATE
from lib.core.threads import getCurrentThreadData, runThreads
from lib.request import inject

def __addPageTextWords():
    wordsList = []

    logger.info("adding words used on web page to the check list")
    pageWords = getPageWordSet(kb.originalPage)

    for word in pageWords:
        word = word.lower()

        if len(word) > 2 and not word[0].isdigit() and word not in wordsList:
            wordsList.append(word)

    return wordsList

def tableExists(tableFile, regex=None):
    result = inject.checkBooleanExpression("%s" % safeStringFormat(BRUTE_TABLE_EXISTS_TEMPLATE, (randomInt(1), randomStr())))
    if result:
        errMsg = "can't use table existence check because of detected invalid results "
        errMsg += "(most probably caused by inability of the used injection "
        errMsg += "to distinguish errornous results)"
        raise sqlmapDataException, errMsg

    tables = getFileItems(tableFile, lowercase=Backend.getIdentifiedDbms() in (DBMS.ACCESS,), unique=True)

    logger.info("checking table existence using items from '%s'" % tableFile)

    tables.extend(__addPageTextWords())
    tables = filterListValue(tables, regex)

    threadData = getCurrentThreadData()
    threadData.shared.count = 0
    threadData.shared.limit = len(tables)
    threadData.shared.outputs = []
    threadData.shared.unique = set()

    def tableExistsThread():
        threadData = getCurrentThreadData()

        while kb.threadContinue:
            kb.locks.count.acquire()
            if threadData.shared.count < threadData.shared.limit:
                table = safeSQLIdentificatorNaming(tables[threadData.shared.count], True)
                threadData.shared.count += 1
                kb.locks.count.release()
            else:
                kb.locks.count.release()
                break

            if conf.db and METADB_SUFFIX not in conf.db:
                fullTableName = "%s%s%s" % (conf.db, '..' if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE) else '.', table)
            else:
                fullTableName = table

            result = inject.checkBooleanExpression("%s" % safeStringFormat(BRUTE_TABLE_EXISTS_TEMPLATE, (randomInt(1), fullTableName)))

            kb.locks.io.acquire()

            if result and table.lower() not in threadData.shared.unique:
                threadData.shared.outputs.append(table)
                threadData.shared.unique.add(table.lower())

                if conf.verbose in (1, 2):
                    clearConsoleLine(True)
                    infoMsg = "[%s] [INFO] retrieved: %s\r\n" % (time.strftime("%X"), table)
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = '%d/%d items (%d%s)' % (threadData.shared.count, threadData.shared.limit, round(100.0*threadData.shared.count/threadData.shared.limit), '%')
                dataToStdout("\r[%s] [INFO] tried %s" % (time.strftime("%X"), status), True)

            kb.locks.io.release()

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
            if conf.db not in kb.data.cachedTables:
                kb.data.cachedTables[conf.db] = [item]
            else:
                kb.data.cachedTables[conf.db].append(item)

    for _ in map(lambda x: (conf.db, x), threadData.shared.outputs):
        if _ not in kb.brute.tables:
            kb.brute.tables.append(_)

    hashDBWrite(HASHDB_KEYS.KB_BRUTE_TABLES, kb.brute.tables, True)

    return kb.data.cachedTables

def columnExists(columnFile, regex=None):
    if not conf.tbl:
        errMsg = "missing table parameter"
        raise sqlmapMissingMandatoryOptionException, errMsg

    result = inject.checkBooleanExpression(safeStringFormat(BRUTE_COLUMN_EXISTS_TEMPLATE, (randomStr(), randomStr())))
    if result:
        errMsg = "can't use column existence check because of detected invalid results "
        errMsg += "(most probably caused by inability of the used injection "
        errMsg += "to distinguish errornous results)"
        raise sqlmapDataException, errMsg

    infoMsg = "checking column existence using items from '%s'" % columnFile
    logger.info(infoMsg)

    columns = getFileItems(columnFile, unique=True)
    columns.extend(__addPageTextWords())
    columns = filterListValue(columns, regex)

    table = safeSQLIdentificatorNaming(conf.tbl, True)
    if conf.db and METADB_SUFFIX not in conf.db:
        table = "%s.%s" % (safeSQLIdentificatorNaming(conf.db), table)

    kb.threadContinue = True
    kb.bruteMode = True

    threadData = getCurrentThreadData()
    threadData.shared.count = 0
    threadData.shared.limit = len(columns)
    threadData.shared.outputs = []

    def columnExistsThread():
        threadData = getCurrentThreadData()

        while kb.threadContinue:
            kb.locks.count.acquire()
            if threadData.shared.count < threadData.shared.limit:
                column = safeSQLIdentificatorNaming(columns[threadData.shared.count])
                threadData.shared.count += 1
                kb.locks.count.release()
            else:
                kb.locks.count.release()
                break

            result = inject.checkBooleanExpression(safeStringFormat(BRUTE_COLUMN_EXISTS_TEMPLATE, (column, table)))

            kb.locks.io.acquire()

            if result:
                threadData.shared.outputs.append(column)

                if conf.verbose in (1, 2):
                    clearConsoleLine(True)
                    infoMsg = "[%s] [INFO] retrieved: %s\r\n" % (time.strftime("%X"), column)
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = '%d/%d items (%d%s)' % (threadData.shared.count, threadData.shared.limit, round(100.0*threadData.shared.count/threadData.shared.limit), '%')
                dataToStdout("\r[%s] [INFO] tried %s" % (time.strftime("%X"), status), True)

            kb.locks.io.release()

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

        kb.data.cachedColumns[conf.db] = {conf.tbl: columns}

        for _ in map(lambda x: (conf.db, conf.tbl, x[0], x[1]), columns.items()):
            if _ not in kb.brute.columns:
                kb.brute.columns.append(_)

        hashDBWrite(HASHDB_KEYS.KB_BRUTE_COLUMNS, kb.brute.columns, True)

    return kb.data.cachedColumns
