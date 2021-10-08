#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import time

from lib.core.common import dataToStdout
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb

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
        self._start = None
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
        This method saves item delta time and shows updated progress bar with calculated eta
        """

        if self._start is None or newAmount > self._max:
            self._start = time.time()
            eta = None
        else:
            delta = time.time() - self._start
            eta = (self._max - self._min) * (1.0 * delta / newAmount) - delta

        self.update(newAmount)
        self.draw(eta)

    def draw(self, eta=None):
        """
        This method draws the progress bar if it has changed
        """

        dataToStdout("\r%s %d/%d%s" % (self._progBar, self._amount, self._max, ("  (ETA %s)" % (self._convertSeconds(int(eta)) if eta is not None else "??:??"))))
        if self._amount >= self._max:
            dataToStdout("\r%s\r" % (" " * self._width))
            kb.prependFlag = False

    def __str__(self):
        """
        This method returns the progress bar string
        """

        return getUnicode(self._progBar)
