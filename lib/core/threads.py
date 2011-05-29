#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import difflib
import threading

from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import advancedDict
from lib.core.exception import sqlmapThreadException

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

def getCurrentThreadData():
    """
    Returns current thread's dependent data
    """

    threadUID = getCurrentThreadUID()
    if threadUID not in kb.threadData:
        kb.threadData[threadUID] = ThreadData()
    return kb.threadData[threadUID]

def runThreads(numThreads, threadFunction, cleanupFunction=None, forwardException=True):
    threads = []

    kb.threadContinue = True
    kb.threadException = False

    if numThreads > 1:
        infoMsg = "starting %d threads" % numThreads
        logger.info(infoMsg)
    else:
        threadFunction()
        return

    # Start the threads
    for numThread in range(numThreads):
        thread = threading.Thread(target=threadFunction, name=str(numThread))
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
                    thread.join(1)

    except KeyboardInterrupt:
        kb.threadContinue = False
        kb.threadException = True

        print
        logger.debug("waiting for threads to finish")

        try:
            while (threading.activeCount() > 1):
                pass

        except KeyboardInterrupt:
            raise sqlmapThreadException, "user aborted (Ctrl+C was pressed multiple times)"

        if forwardException:
            raise

    finally:
        kb.threadContinue = True
        kb.threadException = False

        if cleanupFunction:
            cleanupFunction()
