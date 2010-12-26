#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import threading
import time

from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import getFileItems
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
from lib.request import inject

def tableExists(tableFile):
    tables = getFileItems(tableFile, lowercase=kb.dbms in (DBMS.ACCESS), unique=True)
    tableSet = set(tables)
    retVal = []
    infoMsg = "checking table existence using items from '%s'" % tableFile
    logger.info(infoMsg)
    
    infoMsg = "adding words used on web page to the check list"
    logger.info(infoMsg)
    pageWords = getPageTextWordsSet(kb.originalPage)
    for word in pageWords:
        word = word.lower()
        if len(word) > 2 and not word[0].isdigit() and word not in tableSet:
            tables.append(word)

    count = [0]
    length = len(tables)
    threads = []
    tbllock = threading.Lock()
    iolock = threading.Lock()
    kb.locks.seqLock = threading.Lock()
    kb.threadContinue = True

    def tableExistsThread():
        while count[0] < length and kb.threadContinue:
            tbllock.acquire()
            table = tables[count[0]]
            count[0] += 1
            tbllock.release()

            if conf.db and not conf.db.endswith(METADB_SUFFIX):
                table = "%s.%s" % (conf.db, table)
            result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %d FROM %s)", (randomInt(1), table)))

            iolock.acquire()
            if result:
                retVal.append(table)

                if conf.verbose in (1, 2):
                    clearConsoleLine(True)
                    infoMsg = "\r[%s] [INFO] retrieved: %s\n" % (time.strftime("%X"), table)
                    dataToStdout(infoMsg, True)

            if conf.verbose in (1, 2):
                status = '%d/%d items (%d%s)' % (count[0], length, round(100.0*count[0]/length), '%')
                dataToStdout("\r[%s] [INFO] tried: %s" % (time.strftime("%X"), status), True)
            iolock.release()

    if conf.threads > 1:
        debugMsg = "starting %d threads" % conf.threads
        logger.debug(debugMsg)
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
        kb.locks.seqLock = None
        kb.threadContinue = True
        kb.threadException = False

    clearConsoleLine(True)

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

    columns = getFileItems(columnFile, unique=True)
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
    kb.locks.seqLock = threading.Lock()
    kb.threadContinue = True

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
                dataToStdout("\r[%s] [INFO] tried: %s" % (time.strftime("%X"), status), True)
            iolock.release()

    if conf.threads > 1:
        debugMsg = "starting %d threads" % conf.threads
        logger.debug(debugMsg)
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
        kb.locks.seqLock = None
        kb.threadContinue = True
        kb.threadException = False

    clearConsoleLine(True)

    if not retVal:
        warnMsg = "no column found"
        logger.warn(warnMsg)
    else:
        columns = {}

        for column in retVal:
            result = inject.checkBooleanExpression("%s" % safeStringFormat("EXISTS(SELECT %s FROM %s WHERE RND(%s)>0)", (column, table, column)))

            if result:
                columns[column] = 'numeric'
            else:
                columns[column] = 'non-numeric'

        kb.data.cachedColumns[conf.db] = {conf.tbl: columns}

    return kb.data.cachedColumns
