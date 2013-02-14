#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import getUnicode
from lib.core.common import dataToStdout
from lib.core.data import conf

class ProgressBar(object):
    """
    This class defines methods to update and draw a progress bar
    """

    def __init__(self, minValue=0, maxValue=10, totalWidth=None):
        self._progBar = "[]"
        self._oldProgBar = ""
        self._min = int(minValue)
        self._max = int(maxValue)
        self._span = self._max - self._min
        self._width = totalWidth if totalWidth else conf.progressWidth
        self._amount = 0
        self.update()

    def _convertSeconds(self, value):
        seconds = value
        minutes = seconds / 60
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
        percentDone = int(percentDone)

        # Figure out how many hash bars the percentage should be
        allFull = self._width - 2
        numHashes = (percentDone / 100.0) * allFull
        numHashes = int(round(numHashes))

        # Build a progress bar with an arrow of equal signs
        if numHashes == 0:
            self._progBar = "[>%s]" % (" " * (allFull - 1))
        elif numHashes == allFull:
            self._progBar = "[%s]" % ("=" * allFull)
        else:
            self._progBar = "[%s>%s]" % ("=" * (numHashes - 1),
                                          " " * (allFull - numHashes))

        # Add the percentage at the beginning of the progress bar
        percentString = getUnicode(percentDone) + "%"
        self._progBar = "%s %s" % (percentString, self._progBar)

    def draw(self, eta=0):
        """
        This method draws the progress bar if it has changed
        """

        if self._progBar != self._oldProgBar:
            self._oldProgBar = self._progBar

            if eta and self._amount < self._max:
                dataToStdout("\r%s %d/%d  ETA %s" % (self._progBar, self._amount, self._max, self._convertSeconds(int(eta))))
            else:
                blank = " " * (80 - len("\r%s %d/%d" % (self._progBar, self._amount, self._max)))
                dataToStdout("\r%s %d/%d%s" % (self._progBar, self._amount, self._max, blank))

    def __str__(self):
        """
        This method returns the progress bar string
        """

        return getUnicode(self._progBar)
