#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import difflib
import threading
import time

from thread import error as threadError

from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import AttribDict
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapThreadException
from lib.core.exception import sqlmapValueException
from lib.core.settings import MAX_NUMBER_OF_THREADS
from lib.core.settings import PYVERSION

shared = AttribDict()

class _ThreadData(threading.local):
    """
    Represents thread independent data
    """

    def __init__(self):
        global shared

        self.disableStdOut = False
        self.hashDBCursor = None
        self.lastErrorPage = None
        self.lastHTTPError = None
        self.lastRedirectMsg = None
        self.lastQueryDuration = 0
        self.lastRequestMsg = None
        self.lastRequestUID = 0
        self.retriesCount = 0
        self.seqMatcher = difflib.SequenceMatcher(None)
        self.shared = shared
        self.valueStack = []

ThreadData = _ThreadData()

def getCurrentThreadUID():
    return hash(threading.currentThread())

def readInput(message, default=None):
    pass

def getCurrentThreadData():
    """
    Returns current thread's local data
    """

    global ThreadData

    return ThreadData

def exceptionHandledFunction(threadFunction):
    try:
        threadFunction()
    except KeyboardInterrupt:
        kb.threadContinue = False
        kb.threadException = True
        raise
    except Exception, errMsg:
        # thread is just going to be silently killed
        print
        logger.error("thread %s: %s" % (threading.currentThread().getName(), errMsg))

def runThreads(numThreads, threadFunction, cleanupFunction=None, forwardException=True, threadChoice=False, startThreadMsg=True):
    threads = []

    kb.multiThreadMode = True
    kb.threadContinue = True
    kb.threadException = False

    if threadChoice and numThreads == 1 and any(map(lambda x: x in kb.injection.data, [PAYLOAD.TECHNIQUE.BOOLEAN, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.UNION])):
        while True:
            message = "please enter number of threads? [Enter for %d (current)] " % numThreads
            choice = readInput(message, default=str(numThreads))
            if choice and choice.isdigit():
                if int(choice) > MAX_NUMBER_OF_THREADS:
                    errMsg = "maximum number of used threads is %d avoiding possible connection issues" % MAX_NUMBER_OF_THREADS
                    logger.critical(errMsg)
                else:
                    numThreads = int(choice)
                    break

        if numThreads == 1:
            warnMsg = "running in a single-thread mode. This could take a while."
            logger.warn(warnMsg)

    try:
        if numThreads > 1:
            if startThreadMsg:
                infoMsg = "starting %d threads" % numThreads
                logger.info(infoMsg)
        else:
            threadFunction()
            return

        # Start the threads
        for numThread in range(numThreads):
            thread = threading.Thread(target=exceptionHandledFunction, name=str(numThread), args=[threadFunction])

            # Reference: http://stackoverflow.com/questions/190010/daemon-threads-explanation
            if PYVERSION >= "2.6":
                thread.daemon = True
            else:
                thread.setDaemon(True)

            try:
                thread.start()
            except threadError, errMsg:
                errMsg = "error occured while starting new thread ('%s')" % errMsg
                logger.critical(errMsg)
                break

            threads.append(thread)

        # And wait for them to all finish
        alive = True
        while alive:
            alive = False
            for thread in threads:
                if thread.isAlive():
                    alive = True
                    time.sleep(1)

    except KeyboardInterrupt:
        print
        kb.threadContinue = False
        kb.threadException = True
        logger.info("waiting for threads to finish (Ctrl+C was pressed)")

        try:
            while (threading.activeCount() > 1):
                pass

        except KeyboardInterrupt:
            raise sqlmapThreadException, "user aborted (Ctrl+C was pressed multiple times)"

        if forwardException:
            raise

    except (sqlmapConnectionException, sqlmapValueException), errMsg:
        print
        kb.threadException = True
        logger.error("thread %s: %s" % (threading.currentThread().getName(), errMsg))

    except:
        from lib.core.common import unhandledExceptionMessage

        print
        kb.threadException = True
        errMsg = unhandledExceptionMessage()
        logger.error("thread %s: %s" % (threading.currentThread().getName(), errMsg))
        traceback.print_exc()

    finally:
        kb.multiThreadMode = False
        kb.bruteMode = False
        kb.threadContinue = True
        kb.threadException = False

        if cleanupFunction:
            cleanupFunction()
