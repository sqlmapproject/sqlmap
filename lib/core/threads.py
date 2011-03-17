#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import difflib
import threading

from lib.core.data import kb

class ThreadData():
    """
    Represents thread independent data
    """

    def __init__(self):
        self.disableStdOut      = False
        self.lastErrorPage      = None
        self.lastHTTPError      = None
        self.lastRedirectMsg    = None
        self.lastQueryDuration  = 0
        self.lastRequestUID     = 0
        self.seqMatcher         = difflib.SequenceMatcher(None)
        self.valueStack         = []

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
