#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import time

from lib.core.common import dataToStdout
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.settings import ETA_DISPLAY_SMOOTHING
from lib.core.settings import IS_TTY

class ProgressBar(object):
    """
    This class defines methods to update and draw a progress bar
    """

    def __init__(self, minValue=0, maxValue=10, totalWidth=None):
        self._progBar = "[]"
        self._min = int(minValue)
        self._max = int(maxValue)
        self._span = max(self._max - self._min, 0.001)
        self._width = totalWidth if totalWidth else conf.progressWidth
        self._amount = 0
        self._start = time.time()   # begin timing at construction, so the first completed item already yields an estimate
        self._eta = None            # last estimated seconds-remaining and when it was computed, so tick()
        self._etaAt = None          # can keep the countdown live between (possibly slow) item updates
        self.update()

    def _convertSeconds(self, value):
        seconds = value
        minutes = seconds // 60
        seconds = seconds - (minutes * 60)

        return "%.2d:%.2d" % (minutes, seconds)

    def update(self, newAmount=0):
        """
        This method updates the progress bar
        """

        if newAmount < self._min:
            newAmount = self._min
        elif newAmount > self._max:
            newAmount = self._max

        self._amount = newAmount

        # Figure out the new percent done, round to an integer
        diffFromMin = float(self._amount - self._min)
        percentDone = (diffFromMin / float(self._span)) * 100.0
        percentDone = round(percentDone)
        percentDone = min(100, int(percentDone))

        # Figure out how many hash bars the percentage should be
        allFull = self._width - len("100%% [] %s/%s  (ETA 00:00)" % (self._max, self._max))
        numHashes = (percentDone / 100.0) * allFull
        numHashes = int(round(numHashes))

        # Build a progress bar with an arrow of equal signs
        if numHashes == 0:
            self._progBar = "[>%s]" % (" " * (allFull - 1))
        elif numHashes == allFull:
            self._progBar = "[%s]" % ("=" * allFull)
        else:
            self._progBar = "[%s>%s]" % ("=" * (numHashes - 1), " " * (allFull - numHashes))

        # Add the percentage at the beginning of the progress bar
        percentString = getUnicode(percentDone) + "%"
        self._progBar = "%s %s" % (percentString, self._progBar)

    def progress(self, newAmount):
        """
        Redraw the bar with an ETA from the average time per completed item so far, applied to the items
        still remaining: (elapsed / done) * (max - newAmount). The remaining-item count is (max - newAmount)
        - i.e. at 1/3 it estimates the 2 items left, at 2/3 the 1 left - not just the current item.
        """

        now = time.time()
        if newAmount > self._max:               # counter rollover/reset -> restart timing
            self._start = now
            self._eta = None

        done = newAmount - self._min
        elapsed = now - self._start
        target = (elapsed / done) * (self._max - newAmount) if (done > 0 and elapsed > 0) else None

        if target is None:
            self._eta = None
        elif self._eta is None:
            self._eta = target                  # first estimate: nothing to ease from
        else:
            current = max(0, self._eta - (now - self._etaAt))   # what is on screen now (already decremented by tick())
            self._eta = ETA_DISPLAY_SMOOTHING * current + (1 - ETA_DISPLAY_SMOOTHING) * target   # ease into the fresh estimate

        self._etaAt = now
        self.update(newAmount)
        self.draw(self._eta)

    def tick(self):
        """
        Redraw the current bar with its ETA decremented by real elapsed time, so the countdown stays
        live between updates (e.g. during a long time-based wait) instead of freezing at the last estimate
        """

        eta = None if self._eta is None else max(0, self._eta - (time.time() - self._etaAt))
        self.draw(eta)

    def draw(self, eta=None):
        """
        This method draws the progress bar if it has changed
        """

        if not IS_TTY:      # a progress bar is a terminal animation; suppress it when piped/redirected (as done for other '\r' output)
            return

        dataToStdout("\r%s %d/%d%s" % (self._progBar, self._amount, self._max, ("  (ETA %s)" % (self._convertSeconds(int(eta)) if eta is not None else "??:??"))))
        if self._amount >= self._max:
            dataToStdout("\r%s\r" % (" " * self._width))
            kb.prependFlag = False

    def __str__(self):
        """
        This method returns the progress bar string
        """

        return getUnicode(self._progBar)
