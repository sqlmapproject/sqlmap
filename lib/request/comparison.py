#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import re

from lib.core.common import extractRegexResult
from lib.core.common import getFilteredPageContent
from lib.core.common import listToStrValue
from lib.core.common import removeDynamicContent
from lib.core.common import getLastRequestHTTPError
from lib.core.common import wasLastResponseDBMSError
from lib.core.common import wasLastResponseHTTPError
from lib.core.convert import getBytes
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.settings import DEFAULT_PAGE_ENCODING
from lib.core.settings import DEV_EMAIL_ADDRESS
from lib.core.settings import DIFF_TOLERANCE
from lib.core.settings import HTML_TITLE_REGEX
from lib.core.settings import LOWER_RATIO_BOUND
from lib.core.settings import MAX_DIFFLIB_SEQUENCE_LENGTH
from lib.core.settings import MAX_RATIO
from lib.core.settings import MIN_RATIO
from lib.core.settings import REFLECTED_VALUE_MARKER
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.settings import URI_HTTP_HEADER
from lib.core.threads import getCurrentThreadData
from thirdparty import six

def comparison(page, headers, code=None, getRatioValue=False, pageLength=None):
    try:
        _ = _adjust(_comparison(page, headers, code, getRatioValue, pageLength), getRatioValue)
        return _
    except:
        warnMsg = "there was a KNOWN issue inside the internals regarding the difflib/comparison of pages. "
        warnMsg += "Please report details privately via e-mail to '%s'" % DEV_EMAIL_ADDRESS
        logger.critical(warnMsg)
        raise SqlmapSilentQuitException

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
        threadData.lastComparisonHeaders = listToStrValue(_ for _ in headers.headers if not _.startswith("%s:" % URI_HTTP_HEADER)) if headers else ""
        threadData.lastComparisonPage = page
        threadData.lastComparisonCode = code

    if page is None and pageLength is None:
        return None

    if any((conf.string, conf.notString, conf.regexp)):
        rawResponse = "%s%s" % (listToStrValue(_ for _ in headers.headers if not _.startswith("%s:" % URI_HTTP_HEADER)) if headers else "", page)

        # String to match in page when the query is True
        if conf.string:
            return conf.string in rawResponse

        # String to match in page when the query is False
        if conf.notString:
            if conf.notString in rawResponse:
                return False
            else:
                if kb.errorIsNone and (wasLastResponseDBMSError() or wasLastResponseHTTPError()):
                    return None
                else:
                    return True

        # Regular expression to match in page when the query is True and/or valid
        if conf.regexp:
            return re.search(conf.regexp, rawResponse, re.I | re.M) is not None

    # HTTP code to match when the query is valid
    if conf.code:
        return conf.code == code

    seqMatcher = threadData.seqMatcher
    seqMatcher.set_seq1(kb.pageTemplate)

    if page:
        # In case of an DBMS error page return None
        if kb.errorIsNone and (wasLastResponseDBMSError() or wasLastResponseHTTPError()) and not kb.negativeLogic:
            if not (wasLastResponseHTTPError() and getLastRequestHTTPError() in (conf.ignoreCode or [])):
                return None

        # Dynamic content lines to be excluded before comparison
        if not kb.nullConnection:
            page = removeDynamicContent(page)
            seqMatcher.set_seq1(removeDynamicContent(kb.pageTemplate))

        if not pageLength:
            pageLength = len(page)

    if kb.nullConnection and pageLength:
        if not seqMatcher.a:
            errMsg = "problem occurred while retrieving original page content "
            errMsg += "which prevents sqlmap from continuation. Please rerun, "
            errMsg += "and if the problem persists turn off any optimization switches"
            raise SqlmapNoneDataException(errMsg)

        ratio = 1. * pageLength / len(seqMatcher.a)

        if ratio > 1.:
            ratio = 1. / ratio
    else:
        # Preventing "Unicode equal comparison failed to convert both arguments to Unicode"
        # (e.g. if one page is PDF and the other is HTML)
        if isinstance(seqMatcher.a, six.binary_type) and isinstance(page, six.text_type):
            page = getBytes(page, kb.pageEncoding or DEFAULT_PAGE_ENCODING, "ignore")
        elif isinstance(seqMatcher.a, six.text_type) and isinstance(page, six.binary_type):
            seqMatcher.set_seq1(getBytes(seqMatcher.a, kb.pageEncoding or DEFAULT_PAGE_ENCODING, "ignore"))

        if any(_ is None for _ in (page, seqMatcher.a)):
            return None
        elif seqMatcher.a and page and seqMatcher.a == page:
            ratio = 1.
        elif kb.skipSeqMatcher or seqMatcher.a and page and any(len(_) > MAX_DIFFLIB_SEQUENCE_LENGTH for _ in (seqMatcher.a, page)):
            if not page or not seqMatcher.a:
                return float(seqMatcher.a == page)
            else:
                ratio = 1. * len(seqMatcher.a) / len(page)
                if ratio > 1:
                    ratio = 1. / ratio
        else:
            seq1, seq2 = None, None

            if conf.titles:
                seq1 = extractRegexResult(HTML_TITLE_REGEX, seqMatcher.a)
                seq2 = extractRegexResult(HTML_TITLE_REGEX, page)
            else:
                seq1 = getFilteredPageContent(seqMatcher.a, True) if conf.textOnly else seqMatcher.a
                seq2 = getFilteredPageContent(page, True) if conf.textOnly else page

            if seq1 is None or seq2 is None:
                return None

            if isinstance(seq1, six.binary_type):
                seq1 = seq1.replace(REFLECTED_VALUE_MARKER.encode(), b"")
            elif isinstance(seq1, six.text_type):
                seq1 = seq1.replace(REFLECTED_VALUE_MARKER, "")

            if isinstance(seq2, six.binary_type):
                seq2 = seq2.replace(REFLECTED_VALUE_MARKER.encode(), b"")
            elif isinstance(seq2, six.text_type):
                seq2 = seq2.replace(REFLECTED_VALUE_MARKER, "")

            if kb.heavilyDynamic:
                seq1 = seq1.split("\n" if isinstance(seq1, six.text_type) else b"\n")
                seq2 = seq2.split("\n" if isinstance(seq2, six.text_type) else b"\n")

                key = None
            else:
                key = (hash(seq1), hash(seq2))

            seqMatcher.set_seq1(seq1)
            seqMatcher.set_seq2(seq2)

            if key in kb.cache.comparison:
                ratio = kb.cache.comparison[key]
            else:
                ratio = round(seqMatcher.quick_ratio() if not kb.heavilyDynamic else seqMatcher.ratio(), 3)

            if key:
                kb.cache.comparison[key] = ratio

    # If the url is stable and we did not set yet the match ratio and the
    # current injected value changes the url page content
    if kb.matchRatio is None:
        if ratio >= LOWER_RATIO_BOUND and ratio <= UPPER_RATIO_BOUND:
            kb.matchRatio = ratio
            logger.debug("setting match ratio for current parameter to %.3f" % kb.matchRatio)

    if kb.testMode:
        threadData.lastComparisonRatio = ratio

    # If it has been requested to return the ratio and not a comparison
    # response
    if getRatioValue:
        return ratio

    elif ratio > UPPER_RATIO_BOUND:
        return True

    elif ratio < LOWER_RATIO_BOUND:
        return False

    elif kb.matchRatio is None:
        return None

    else:
        return (ratio - kb.matchRatio) > DIFF_TOLERANCE
