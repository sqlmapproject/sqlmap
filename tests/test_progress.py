#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The textual progress bar (lib/utils/progress.py) used during multi-item
extraction. Pure rendering/clamping logic plus ETA formatting.
"""

import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testutils import bootstrap
bootstrap()

import lib.utils.progress as progress_mod
from lib.utils.progress import ProgressBar


class TestProgressBar(unittest.TestCase):
    def test_initial_is_zero_percent(self):
        pb = ProgressBar(0, 100, 78)
        self.assertTrue(str(pb).startswith("0%"), msg=str(pb))

    def test_full_is_hundred_percent(self):
        pb = ProgressBar(0, 100, 78)
        pb.update(100)
        self.assertTrue(str(pb).startswith("100%"), msg=str(pb))

    def test_half_is_fifty_percent(self):
        pb = ProgressBar(0, 100, 78)
        pb.update(50)
        self.assertIn("50%", str(pb))

    def test_update_clamps_below_min(self):
        pb = ProgressBar(10, 20, 78)
        pb.update(-5)
        self.assertTrue(str(pb).startswith("0%"))

    def test_update_clamps_above_max(self):
        pb = ProgressBar(0, 10, 78)
        pb.update(999)
        self.assertTrue(str(pb).startswith("100%"))

    def test_convert_seconds(self):
        pb = ProgressBar(0, 10, 78)
        self.assertEqual(pb._convertSeconds(0), "00:00")
        self.assertEqual(pb._convertSeconds(65), "01:05")
        self.assertEqual(pb._convertSeconds(600), "10:00")

    def test_progress_draws_eta_after_second_call(self):
        captured = []
        real = progress_mod.dataToStdout
        progress_mod.dataToStdout = lambda data, *a, **k: captured.append(data)
        try:
            pb = ProgressBar(0, 10, 78)
            pb.progress(0)               # first call only seeds the timer (eta None)
            time.sleep(0.01)             # let some wall-clock elapse so eta is computable
            pb.progress(5)               # second call computes and draws a real ETA
        finally:
            progress_mod.dataToStdout = real

        self.assertTrue(captured, msg="progress() never wrote to stdout")
        last = captured[-1]
        # the drawn bar must carry an ETA token with an mm:ss timer (not the ??:?? placeholder)
        self.assertIn("(ETA ", last, msg="no ETA token drawn: %r" % last)
        self.assertNotIn("??:??", last, msg="ETA was not computed on the second call: %r" % last)
        self.assertTrue(re.search(r"\(ETA \d{2}:\d{2}\)", last),
                        msg="ETA token missing an mm:ss timer: %r" % last)


if __name__ == "__main__":
    unittest.main()
