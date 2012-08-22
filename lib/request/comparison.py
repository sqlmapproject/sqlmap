#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import extractRegexResult
from lib.core.common import getFilteredPageContent
from lib.core.common import listToStrValue
from lib.core.common import removeDynamicContent
from lib.core.common import wasLastRequestDBMSError
from lib.core.common import wasLastRequestHTTPError
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapNoneDataException
from lib.core.settings import DEFAULT_PAGE_ENCODING
from lib.core.settings import DIFF_TOLERANCE
from lib.core.settings import HTML_TITLE_REGEX
from lib.core.settings import MIN_RATIO
from lib.core.settings import MAX_RATIO
from lib.core.settings import LOWER_RATIO_BOUND
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.threads import getCurrentThreadData

def comparison(page, headers, code=None, getRatioValue=False, pageLength=None):
    _ = _adjust(_comparison(page, headers, code, getRatioValue, pageLength), getRatioValue)
    return _

def _adjust(condition, getRatioValue):
    if not any((conf.string, conf.notString, conf.regexp, conf.code)):
        # Negative logic approach is used in raw page comparison scheme as that what is "different" than original
        # PAYLOAD.WHERE.NEGATIVE response is considered as True; in switch based approach negative logic is not
        # applied as that what is by user considered as True is that what is returned by the comparison mechanism
        # itself
        retVal = not condition if kb.negativeLogic and condition is not None and not getRatioValue else condition
    else:
        retVal = condition if not getRatioValue else (MAX_RATIO if condition else MIN_RATIO)

    return retVal

def _comparison(page, headers, code, getRatioValue, pageLength):
    threadData = getCurrentThreadData()

    if kb.testMode:
        threadData.lastComparisonPage = page

    if page is None and pageLength is None:
        return None

    seqMatcher = threadData.seqMatcher
    seqMatcher.set_seq1(kb.pageTemplate)

    if any((conf.string, conf.notString, conf.regexp)):
        rawResponse = "%s%s" % (listToStrValue(headers.headers if headers else ""), page)

        # String to match in page when the query is True and/or valid
        if conf.string:
            return conf.string in rawResponse

        # String to match in page when the query is False and/or invalid
        if conf.notString:
            return conf.notString not in rawResponse

        # Regular expression to match in page when the query is True and/or valid
        if conf.regexp:
            return re.search(conf.regexp, rawResponse, re.I | re.M) is not None

    # HTTP code to match when the query is valid
    if isinstance(code, int) and conf.code:
        return conf.code == code

    if page:
        # In case of an DBMS error page return None
        if kb.errorIsNone and (wasLastRequestDBMSError() or wasLastRequestHTTPError()):
            return None

        # Dynamic content lines to be excluded before comparison
        if not kb.nullConnection:
            page = removeDynamicContent(page)
            seqMatcher.set_seq1(removeDynamicContent(kb.pageTemplate))

        if not pageLength:
            pageLength = len(page)

    if kb.nullConnection and pageLength:
        if not seqMatcher.a:
            errMsg = "problem occured while retrieving original page content "
            errMsg += "which prevents sqlmap from continuation. Please rerun, "
            errMsg += "and if the problem persists turn off any optimization switches"
            raise sqlmapNoneDataException, errMsg

        ratio = 1. * pageLength / len(seqMatcher.a)

        if ratio > 1.:
            ratio = 1. / ratio
    else:
        # Preventing "Unicode equal comparison failed to convert both arguments to Unicode"
        # (e.g. if one page is PDF and the other is HTML)
        if isinstance(seqMatcher.a, str) and isinstance(page, unicode):
            page = page.encode(kb.pageEncoding or DEFAULT_PAGE_ENCODING, 'ignore')
        elif isinstance(seqMatcher.a, unicode) and isinstance(page, str):
            seqMatcher.a = seqMatcher.a.encode(kb.pageEncoding or DEFAULT_PAGE_ENCODING, 'ignore')

        seq1, seq2 = None, None

        if conf.titles:
            seq1 = extractRegexResult(HTML_TITLE_REGEX, seqMatcher.a)
            seq2 = extractRegexResult(HTML_TITLE_REGEX, page)
        else:
            seq1 = getFilteredPageContent(seqMatcher.a, True) if conf.textOnly else seqMatcher.a
            seq2 = getFilteredPageContent(page, True) if conf.textOnly else page

        if seq1 is not None:
            seqMatcher.set_seq1(seq1)

        if seq2 is not None:
            seqMatcher.set_seq2(seq2)

        if seq1 is None or seq2 is None:
            return None
        else:
            ratio = round(seqMatcher.quick_ratio(), 3)

    # If the url is stable and we did not set yet the match ratio and the
    # current injected value changes the url page content
    if kb.matchRatio is None:
        if ratio >= LOWER_RATIO_BOUND and ratio <= UPPER_RATIO_BOUND:
            kb.matchRatio = ratio
            logger.debug("setting match ratio for current parameter to %.3f" % kb.matchRatio)

    # If it has been requested to return the ratio and not a comparison
    # response
    if getRatioValue:
        return ratio

    elif ratio > UPPER_RATIO_BOUND:
        return True

    elif kb.matchRatio is None:
        return None

    else:
        return (ratio - kb.matchRatio) > DIFF_TOLERANCE
