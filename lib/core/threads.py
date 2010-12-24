#!/usr/bin/env python

"""
$Id: unescaper.py 2635 2010-12-10 10:52:55Z inquisb $

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import threading

from lib.core.data import kb

class ThreadData():
    """
    Represents thread independent data
    """

    def __init__(self):
        self.lastErrorPage = None
        self.lastQueryDuration = 0
        self.lastRequestUID = 0
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

