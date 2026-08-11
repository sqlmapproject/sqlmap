#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Switch '--profile' (lib/core/profiling.py). The profiled statement must resolve
'start' from an explicit namespace: on pip installs __main__ is the console
script, not sqlmap.py, so relying on it raised NameError (#6096). This test runs
under a unittest __main__ that has no 'start' either, so it covers that case.
"""

import os
import pstats
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.controller.controller as controller
from lib.core.profiling import profile


class TestProfiling(unittest.TestCase):
    def setUp(self):
        self._saved = controller.start
        self._dir = tempfile.mkdtemp()
        self._out = os.path.join(self._dir, "sqlmap_profile.raw")

    def tearDown(self):
        controller.start = self._saved
        shutil.rmtree(self._dir, ignore_errors=True)

    def test_profile_does_not_need_start_in_main(self):
        calls = []
        controller.start = lambda *args, **kwargs: calls.append(True)

        profile(self._out)

        self.assertEqual(calls, [True], msg="start() was never run under the profiler")
        self.assertTrue(os.path.exists(self._out), msg="no raw profile written")
        self.assertTrue(pstats.Stats(self._out).stats, msg="raw profile holds no stats")

    def test_profile_overwrites_a_stale_output_file(self):
        controller.start = lambda *args, **kwargs: None

        with open(self._out, "wb") as f:
            f.write(b"not a pstats file")

        profile(self._out)
        self.assertTrue(pstats.Stats(self._out).stats)


if __name__ == "__main__":
    unittest.main()
