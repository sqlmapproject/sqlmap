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
        realTty = progress_mod.IS_TTY
        progress_mod.dataToStdout = lambda data, *a, **k: captured.append(data)
        progress_mod.IS_TTY = True    # draw() only animates on a terminal
        try:
            pb = ProgressBar(0, 10, 78)
            pb.progress(0)               # first call only seeds the timer (eta None)
            time.sleep(0.01)             # let some wall-clock elapse so eta is computable
            pb.progress(5)               # second call computes and draws a real ETA
        finally:
            progress_mod.dataToStdout = real
            progress_mod.IS_TTY = realTty

        self.assertTrue(captured, msg="progress() never wrote to stdout")
        last = captured[-1]
        # the drawn bar must carry an ETA token with an mm:ss timer (not the ??:?? placeholder)
        self.assertIn("(ETA ", last, msg="no ETA token drawn: %r" % last)
        self.assertNotIn("??:??", last, msg="ETA was not computed on the second call: %r" % last)
        self.assertTrue(re.search(r"\(ETA \d{2}:\d{2}\)", last),
                        msg="ETA token missing an mm:ss timer: %r" % last)

    def test_eta_available_from_first_completed_item(self):
        captured = []
        real = progress_mod.dataToStdout
        realTty = progress_mod.IS_TTY
        progress_mod.dataToStdout = lambda data, *a, **k: captured.append(data)
        progress_mod.IS_TTY = True
        try:
            pb = ProgressBar(0, 5, 78)
            pb._start = pb._lastTime = time.time() - 2.0   # one item took ~2s -> estimate must appear now, at 1/5
            pb.progress(1)
        finally:
            progress_mod.dataToStdout = real
            progress_mod.IS_TTY = realTty

        last = captured[-1]
        self.assertNotIn("??:??", last, msg="no ETA at the first item: %r" % last)
        m = re.search(r"\(ETA (\d{2}):(\d{2})\)", last)
        secs = int(m.group(1)) * 60 + int(m.group(2))
        self.assertTrue(7 <= secs <= 9, msg="ETA not ~8s (2s/item x 4 remaining): %r" % last)   # not the 2x-optimistic ~4s

    def test_eta_reflects_remaining_item_count(self):
        # at a constant 10s/item pace: 1/3 must estimate the 2 items left (~20s), 2/3 the 1 left (~10s) -
        # i.e. (max - done) items, not just the current one. Fresh bars so each is a first (unsmoothed) estimate.
        captured = []
        real = progress_mod.dataToStdout
        realTty = progress_mod.IS_TTY
        progress_mod.dataToStdout = lambda data, *a, **k: captured.append(data)
        progress_mod.IS_TTY = True

        def drawnEta():
            m = re.search(r"\(ETA (\d{2}):(\d{2})\)", captured[-1])
            self.assertTrue(m, msg="no ETA drawn: %r" % captured[-1])
            return int(m.group(1)) * 60 + int(m.group(2))

        try:
            a = ProgressBar(0, 3, 78)
            a._start = time.time() - 10.0      # 1 done in 10s -> 10s/item, 2 remaining -> ~20s
            a.progress(1)
            eta1 = drawnEta()

            b = ProgressBar(0, 3, 78)
            b._start = time.time() - 20.0      # 2 done in 20s -> 10s/item, 1 remaining -> ~10s
            b.progress(2)
            eta2 = drawnEta()
        finally:
            progress_mod.dataToStdout = real
            progress_mod.IS_TTY = realTty

        self.assertTrue(18 <= eta1 <= 22, msg="1/3 should estimate 2 remaining (~20s): %ds" % eta1)
        self.assertTrue(8 <= eta2 <= 12, msg="2/3 should estimate 1 remaining (~10s): %ds" % eta2)

    def test_new_estimate_is_eased_not_snapped(self):
        # when a fresh estimate is far from the value currently on screen, the drawn ETA must land
        # between the two (smoothed), not snap straight to the new target
        captured = []
        real = progress_mod.dataToStdout
        realTty = progress_mod.IS_TTY
        progress_mod.dataToStdout = lambda data, *a, **k: captured.append(data)
        progress_mod.IS_TTY = True
        try:
            pb = ProgressBar(0, 10, 78)
            pb._eta = 8.0                       # currently showing ~8s...
            pb._etaAt = time.time()
            pb._start = time.time() - 2.0       # ...but the fresh target is (2/1)*(10-1) = 18s
            pb.progress(1)
        finally:
            progress_mod.dataToStdout = real
            progress_mod.IS_TTY = realTty

        m = re.search(r"\(ETA (\d{2}):(\d{2})\)", captured[-1])
        secs = int(m.group(1)) * 60 + int(m.group(2))
        self.assertTrue(10 <= secs <= 16, msg="ETA snapped instead of easing between 8 and 18: %ds" % secs)

    def test_tick_counts_down_from_stored_eta(self):
        captured = []
        real = progress_mod.dataToStdout
        realTty = progress_mod.IS_TTY
        progress_mod.dataToStdout = lambda data, *a, **k: captured.append(data)
        progress_mod.IS_TTY = True
        try:
            pb = ProgressBar(0, 10, 78)
            pb.update(5)
            pb._eta = 100                       # a 100s estimate...
            pb._etaAt = time.time() - 30        # ...taken 30s ago -> tick() must show ~70s
            pb.tick()
        finally:
            progress_mod.dataToStdout = real
            progress_mod.IS_TTY = realTty

        m = re.search(r"\(ETA (\d{2}):(\d{2})\)", captured[-1])
        self.assertTrue(m, msg="no mm:ss ETA drawn: %r" % captured[-1])
        secs = int(m.group(1)) * 60 + int(m.group(2))
        self.assertTrue(66 <= secs <= 71, msg="ETA not decremented to ~70s: %r" % captured[-1])

    def test_tick_clamps_at_zero_when_overdue(self):
        captured = []
        real = progress_mod.dataToStdout
        realTty = progress_mod.IS_TTY
        progress_mod.dataToStdout = lambda data, *a, **k: captured.append(data)
        progress_mod.IS_TTY = True
        try:
            pb = ProgressBar(0, 10, 78)
            pb.update(5)
            pb._eta = 5
            pb._etaAt = time.time() - 60        # long overdue -> must clamp to 00:00, never negative
            pb.tick()
        finally:
            progress_mod.dataToStdout = real
            progress_mod.IS_TTY = realTty

        self.assertIn("(ETA 00:00)", captured[-1], msg=captured[-1])

    def test_no_draw_when_not_tty(self):
        captured = []
        real = progress_mod.dataToStdout
        realTty = progress_mod.IS_TTY
        progress_mod.dataToStdout = lambda data, *a, **k: captured.append(data)
        progress_mod.IS_TTY = False   # piped/redirected: no animated bar should reach the stream
        try:
            pb = ProgressBar(0, 10, 78)
            for i in range(1, 11):
                pb.progress(i)
        finally:
            progress_mod.dataToStdout = real
            progress_mod.IS_TTY = realTty

        self.assertEqual(captured, [], msg="progress bar leaked to a non-TTY stream: %r" % captured)


if __name__ == "__main__":
    unittest.main()
