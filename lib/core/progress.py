#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import getUnicode
from lib.core.common import dataToStdout
from lib.core.data import conf

class ProgressBar:
    """
    This class defines methods to update and draw a progress bar
    """

    def __init__(self, minValue=0, maxValue=10, totalWidth=None):
        self.__progBar = "[]"
        self.__oldProgBar = ""
        self.__min = int(minValue)
        self.__max = int(maxValue)
        self.__span = self.__max - self.__min
        self.__width = totalWidth if totalWidth else conf.progressWidth
        self.__amount = 0
        self.update()

    def __convertSeconds(self, value):
        minutes = value / 60
        seconds = value - (minutes * 60)

        return "%.2d:%.2d" % (minutes, seconds)

    def update(self, newAmount=0):
        """
        This method updates the progress bar
        """

        if newAmount < self.__min:
            newAmount = self.__min
        elif newAmount > self.__max:
            newAmount = self.__max

        self.__amount = newAmount

        # Figure out the new percent done, round to an integer
        diffFromMin = float(self.__amount - self.__min)
        percentDone = (diffFromMin / float(self.__span)) * 100.0
        percentDone = round(percentDone)
        percentDone = int(percentDone)

        # Figure out how many hash bars the percentage should be
        allFull = self.__width - 2
        numHashes = (percentDone / 100.0) * allFull
        numHashes = int(round(numHashes))

        # Build a progress bar with an arrow of equal signs
        if numHashes == 0:
            self.__progBar = "[>%s]" % (" " * (allFull - 1))
        elif numHashes == allFull:
            self.__progBar = "[%s]" % ("=" * allFull)
        else:
            self.__progBar = "[%s>%s]" % ("=" * (numHashes - 1),
                                          " " * (allFull - numHashes))

        # Add the percentage at the beginning of the progress bar
        percentString = getUnicode(percentDone) + "%"
        self.__progBar = "%s %s" % (percentString, self.__progBar)

    def draw(self, eta=0):
        """
        This method draws the progress bar if it has changed
        """

        if self.__progBar != self.__oldProgBar:
            self.__oldProgBar = self.__progBar

            if eta and self.__amount < self.__max:
                dataToStdout("\r%s %d/%d  ETA %s" % (self.__progBar, self.__amount, self.__max, self.__convertSeconds(int(eta))))
            else:
                blank = " " * (80 - len("\r%s %d/%d" % (self.__progBar, self.__amount, self.__max)))
                dataToStdout("\r%s %d/%d%s" % (self.__progBar, self.__amount, self.__max, blank))

    def __str__(self):
        """
        This method returns the progress bar string
        """

        return getUnicode(self.__progBar)
