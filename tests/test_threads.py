#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Threading helpers in lib/core/threads.py: the thread-local data model,
current-thread accessors, the exception-isolating wrapper, and runThreads()
(the worker-pool driver used throughout extraction). Exercised with trivial,
fast, network-free workers.
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

from lib.core import threads as T
from lib.core.data import conf, kb
from thirdparty.six.moves import queue as _queue


class TestThreadData(unittest.TestCase):
    def test_reset_initializes_fields(self):
        td = T.getCurrentThreadData()
        td.retriesCount = 5
        td.reset()
        self.assertEqual(td.retriesCount, 0)
        self.assertEqual(td.valueStack, [])
        self.assertFalse(td.disableStdOut)

    def test_get_current_thread_data_is_threadlocal(self):
        # ThreadData subclasses threading.local: the wrapper object is shared, but its
        # ATTRIBUTE STATE is per-thread. Verify both: same object, independent state.
        main = T.getCurrentThreadData()
        self.assertIs(main, T.getCurrentThreadData())      # stable within a thread

        main.retriesCount = 111

        other = {}

        def worker():
            td = T.getCurrentThreadData()
            other["same_obj"] = (td is main)
            # a fresh thread gets reset()-initialised state, NOT the main thread's 111
            other["retries_seen"] = td.retriesCount
            td.retriesCount = 222

        t = threading.Thread(target=worker)
        t.start()
        t.join()

        # the wrapper object identity is shared (threading.local semantics) ...
        self.assertTrue(other["same_obj"])
        # ... but the worker never saw the main thread's mutation (thread-local state) ...
        self.assertEqual(other["retries_seen"], 0)
        # ... and the worker's own mutation did not leak back into the main thread
        self.assertEqual(main.retriesCount, 111)

    def test_get_current_thread_name(self):
        self.assertEqual(T.getCurrentThreadName(), threading.current_thread().name)


class TestExceptionHandledFunction(unittest.TestCase):
    def test_success_runs_function(self):
        calls = []
        T.exceptionHandledFunction(lambda: calls.append(1))
        self.assertEqual(calls, [1])

    def _capture_errors(self, silent):
        """Run a raising worker, returning the list of logged error messages."""
        errors = []

        class _Rec(object):
            def error(self, msg, *a):
                errors.append(msg % a if a else msg)

            def __getattr__(self, name):
                return lambda *a, **k: None

        saved_logger = T.logger
        saved_continue = kb.get("threadContinue")
        saved_multi = kb.get("multipleCtrlC")
        T.logger = _Rec()
        kb.threadContinue = True
        kb.multipleCtrlC = False
        try:
            # must never propagate, regardless of the silent flag
            T.exceptionHandledFunction(lambda: 1 / 0, silent=silent)
        finally:
            T.logger = saved_logger
            kb.threadContinue = saved_continue
            kb.multipleCtrlC = saved_multi
        return errors

    def test_non_silent_logs_error(self):
        # silent=False (with threadContinue) routes the swallowed exception to logger.error
        errors = self._capture_errors(silent=False)
        self.assertTrue(errors, msg="non-silent mode logged no error")
        self.assertTrue(any("ZeroDivisionError" in e for e in errors),
                        msg="error message did not name the exception: %r" % errors)

    def test_silent_logs_nothing(self):
        # silent=True gates the logging: the exception is swallowed without any error log
        errors = self._capture_errors(silent=True)
        self.assertEqual(errors, [], msg="silent mode unexpectedly logged: %r" % errors)

    def test_keyboardinterrupt_propagates(self):
        def boom():
            raise KeyboardInterrupt
        self.assertRaises(KeyboardInterrupt, T.exceptionHandledFunction, boom)


class TestSetDaemon(unittest.TestCase):
    def test_sets_daemon_flag(self):
        t = threading.Thread(target=lambda: None)
        T.setDaemon(t)
        self.assertTrue(t.daemon)


class TestRunThreads(unittest.TestCase):
    def setUp(self):
        self._saved = {k: conf.get(k) for k in ("threads", "hashDB")}
        conf.hashDB = None

    def tearDown(self):
        for k, v in self._saved.items():
            conf[k] = v

    def test_workers_drain_shared_queue(self):
        q = _queue.Queue()
        total = 50
        for i in range(total):
            q.put(i)
        seen = []
        lock = threading.Lock()

        def worker():
            while True:
                try:
                    item = q.get_nowait()
                except _queue.Empty:
                    break
                with lock:
                    seen.append(item)

        conf.threads = 4
        T.runThreads(4, worker, startThreadMsg=False)
        self.assertEqual(sorted(seen), list(range(total)))

    def test_single_thread_runs_worker(self):
        calls = []
        conf.threads = 1
        T.runThreads(1, lambda: calls.append(1), startThreadMsg=False)
        self.assertEqual(calls, [1])

    def test_cleanup_function_invoked(self):
        flags = []
        conf.threads = 2
        T.runThreads(2, lambda: None,
                     cleanupFunction=lambda: flags.append(1),
                     startThreadMsg=False)
        self.assertTrue(flags)


if __name__ == "__main__":
    unittest.main()
