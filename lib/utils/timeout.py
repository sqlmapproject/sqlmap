#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import threading

from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import TIMEOUT_STATE

def timeout(func, args=(), kwargs={}, duration=1, default=None):
    class InterruptableThread(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.result = None
            self.timeout_state = None

        def run(self):
            try:
                self.result = func(*args, **kwargs)
                self.timeout_state = TIMEOUT_STATE.NORMAL
            except Exception as ex:
                logger.log(CUSTOM_LOGGING.TRAFFIC_IN, ex)
                self.result = default
                self.timeout_state = TIMEOUT_STATE.EXCEPTION

    thread = InterruptableThread()
    thread.start()
    thread.join(duration)

    if thread.isAlive():
        return default, TIMEOUT_STATE.TIMEOUT
    else:
        return thread.result, thread.timeout_state
