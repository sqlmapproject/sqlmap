#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import threading

from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING

def timeout(func, args=(), kwargs={}, duration=1, default=None):
    class InterruptableThread(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.result = None

        def run(self):
            try:
                self.result = func(*args, **kwargs)
            except Exception, msg:
                logger.log(CUSTOM_LOGGING.TRAFFIC_IN, msg)
                self.result = default

    thread = InterruptableThread()
    thread.start()
    thread.join(duration)

    if thread.isAlive():
        return default
    else:
        return thread.result
