#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""



from lib.core.common import dataToStdout


class ProgressBar:
    """
    This class defines methods to update and draw a progress bar
    """

    def __init__(self, minValue=0, maxValue=10, totalWidth=54):
        self.__progBar = "[]"
        self.__oldProgBar = ""
        self.__min = minValue
        self.__max = maxValue
        self.__span = maxValue - minValue
        self.__width = totalWidth
        self.__amount = 0
        self.update()


    def __convertSeconds(self, value):
        seconds = value
        minutes = seconds / 60
        seconds = seconds - (minutes * 60)

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
        percentString = str(percentDone) + "%"
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

        return str(self.__progBar)
