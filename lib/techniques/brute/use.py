#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
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
from lib.core.common import safeStringFormat
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.exception import sqlmapMissingMandatoryOptionException
from lib.core.exception import sqlmapThreadException
from lib.core.settings import METADB_SUFFIX
from lib.core.session import safeFormatString
from lib.request import inject

def tableExists(tableFile, regex=None):
    tables = getFileItems(tableFile, lowercase=Backend.getIdentifiedDbms() in (DBMS.ACCESS), unique=True)
    retVal = []

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
    count = [0]
    length = len(tables)
    threads = []
    tbllock = threading.Lock()
    iolock = threading.Lock()
    kb.threadContinue = True
    kb.suppressSession = True

    def tableExistsThread():
        while count[0] < length and kb.threadContinue:
            tbllock.acquire()
            table = tables[count[0]]
            count[0] += 1
            tbllock.release()

            if conf.db and not conf.db.endswith(METADB_SUFFIX):
                fullTableName = "%s.%s" % (conf.db, table)
            else:
                fullTableName = table

            result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %d FROM %s)", (randomInt(1), fullTableName)))

            iolock.acquire()

            if result:
                retVal.append(table)

                dataToSessionFile("[%s][%s][%s][TABLE_EXISTS][%s]\n" % (conf.url,\
                  kb.injection.place, safeFormatString(conf.parameters[kb.injection.place]),\
                  safeFormatString(fullTableName)))

                if conf.verbose in (1, 2):
                    clearConsoleLine(True)
                    infoMsg = "\r[%s] [INFO] retrieved: %s\n" % (time.strftime("%X"), table)
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = '%d/%d items (%d%s)' % (count[0], length, round(100.0*count[0]/length), '%')
                dataToStdout("\r[%s] [INFO] tried %s" % (time.strftime("%X"), status), True)

            iolock.release()

    if conf.threads > 1:
        infoMsg = "starting %d threads" % conf.threads
        logger.info(infoMsg)
    else:
        warnMsg = "running in a single-thread mode. this could take a while."
        logger.warn(warnMsg)

    # Start the threads
    for numThread in range(conf.threads):
        thread = threading.Thread(target=tableExistsThread, name=str(numThread))
        thread.start()
        threads.append(thread)

    # And wait for them to all finish
    try:
        alive = True

        while alive:
            alive = False

            for thread in threads:
                if thread.isAlive():
                    alive = True
                    thread.join(5)
    except KeyboardInterrupt:
        kb.threadContinue = False
        kb.threadException = True

        print
        logger.debug("waiting for threads to finish")

        try:
            while (threading.activeCount() > 1):
                pass

        except KeyboardInterrupt:
            raise sqlmapThreadException, "user aborted"
    finally:
        kb.threadContinue = True
        kb.threadException = False
        kb.suppressSession = False

    clearConsoleLine(True)
    dataToStdout("\n")

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

def columnExists(columnFile, regex=None):
    if not conf.tbl:
        errMsg = "missing table parameter"
        raise sqlmapMissingMandatoryOptionException, errMsg

    columns = getFileItems(columnFile, unique=True)
    columns = filterListValue(columns, regex)

    if conf.db and not conf.db.endswith(METADB_SUFFIX):
        table = "%s.%s" % (conf.db, conf.tbl)
    else:
        table = conf.tbl

    retVal = []
    infoMsg = "checking column existence using items from '%s'" % columnFile
    logger.info(infoMsg)

    count = [0]
    length = len(columns)
    threads = []
    collock = threading.Lock()
    iolock = threading.Lock()
    kb.threadContinue = True
    kb.suppressSession = True

    def columnExistsThread():
        while count[0] < length and kb.threadContinue:
            collock.acquire()
            column = columns[count[0]]
            count[0] += 1
            collock.release()

            result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s)", (column, table)))

            iolock.acquire()

            if result:
                retVal.append(column)

                if conf.verbose in (1, 2):
                    clearConsoleLine(True)
                    infoMsg = "\r[%s] [INFO] retrieved: %s\n" % (time.strftime("%X"), column)
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = '%d/%d items (%d%s)' % (count[0], length, round(100.0*count[0]/length), '%')
                dataToStdout("\r[%s] [INFO] tried %s" % (time.strftime("%X"), status), True)

            iolock.release()

    if conf.threads > 1:
        infoMsg = "starting %d threads" % conf.threads
        logger.info(infoMsg)
    else:
        warnMsg = "running in a single-thread mode. this could take a while."
        logger.warn(warnMsg)

    # Start the threads
    for numThread in range(conf.threads):
        thread = threading.Thread(target=columnExistsThread, name=str(numThread))
        thread.start()
        threads.append(thread)

    # And wait for them to all finish
    try:
        alive = True

        while alive:
            alive = False

            for thread in threads:
                if thread.isAlive():
                    alive = True
                    thread.join(5)
    except KeyboardInterrupt:
        kb.threadContinue = False
        kb.threadException = True

        print
        logger.debug("waiting for threads to finish")

        try:
            while (threading.activeCount() > 1):
                pass

        except KeyboardInterrupt:
            raise sqlmapThreadException, "user aborted"
    finally:
        kb.threadContinue = True
        kb.threadException = False
        kb.suppressSession = False

    clearConsoleLine(True)
    dataToStdout("\n")

    if not retVal:
        warnMsg = "no column found"
        logger.warn(warnMsg)
    else:
        columns = {}

        for column in retVal:
            result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE ROUND(%s)=ROUND(%s))", (column, table, column, column)))

            if result:
                columns[column] = 'numeric'
            else:
                columns[column] = 'non-numeric'

            dataToSessionFile("[%s][%s][%s][COLUMN_EXISTS][%s..%s %s]\n" % (conf.url, kb.injection.place,\
              safeFormatString(conf.parameters[kb.injection.place]), safeFormatString(table),\
              safeFormatString(column), safeFormatString(columns[column])))

        kb.data.cachedColumns[conf.db] = {conf.tbl: columns}

    return kb.data.cachedColumns
