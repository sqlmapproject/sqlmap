#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import difflib
import threading
import time

from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import advancedDict
from lib.core.exception import sqlmapThreadException
from lib.core.settings import MAX_NUMBER_OF_THREADS
from lib.core.settings import PYVERSION

shared = advancedDict()

class ThreadData():
    """
    Represents thread independent data
    """

    def __init__(self):
        global shared

        self.disableStdOut = False
        self.lastErrorPage = None
        self.lastHTTPError = None
        self.lastRedirectMsg = None
        self.lastQueryDuration = 0
        self.lastRequestUID = 0
        self.retriesCount = 0
        self.seqMatcher = difflib.SequenceMatcher(None)
        self.shared = shared
        self.valueStack = []

def getCurrentThreadUID():
    return hash(threading.currentThread())

def readInput(message, default=None):
    pass

def getCurrentThreadData():
    """
    Returns current thread's dependent data
    """

    threadUID = getCurrentThreadUID()
    if threadUID not in kb.threadData:
        kb.threadData[threadUID] = ThreadData()
    return kb.threadData[threadUID]

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

def runThreads(numThreads, threadFunction, cleanupFunction=None, forwardException=True, threadChoice=False):
    threads = []

    kb.multiThreadMode = True
    kb.threadContinue = True
    kb.threadException = False

    if threadChoice and numThreads == 1:
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

    if numThreads > 1:
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
                    time.sleep(1)

    except KeyboardInterrupt:
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

    finally:
        kb.multiThreadMode = False
        kb.bruteMode = False
        kb.threadContinue = True
        kb.threadException = False

        if cleanupFunction:
            cleanupFunction()
