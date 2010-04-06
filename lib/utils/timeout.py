#!/usr/bin/env python

import threading

def timeout(func, args=(), kwargs={}, duration=1, default=None):
    class InterruptableThread(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.exceeded = False
            self.result = None

        def run(self):
            try:
                self.result = func(*args, **kwargs)
            except:
                self.result = default

    thread = InterruptableThread()
    thread.start()
    thread.join(duration)
    self.exceeded = thread.isAlive()
    if self.exceeded:
        return default
    else:
        return thread.result
