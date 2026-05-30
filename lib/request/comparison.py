#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
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
from lib.core.settings import DEFAULT_PAGE_ENCODING
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

MATCH_RATIO_MIN_SAMPLES = 3
MATCH_RATIO_MAX_SAMPLES = 7

# Multiplier applied to the observed jitter (MAD) when computing the
# adaptive decision tolerance. Roughly mimics ~2 sigma for a normal
# distribution while staying robust against outliers.
JITTER_TOLERANCE_MULTIPLIER = 3.0

def _toBytes(value):
    if value is None:
        return b""
    elif isinstance(value, six.binary_type):
        return value
    elif isinstance(value, six.text_type):
        return getBytes(value, kb.pageEncoding or DEFAULT_PAGE_ENCODING, "ignore")
    else:
        return getBytes(six.text_type(value), kb.pageEncoding or DEFAULT_PAGE_ENCODING, "ignore")

def _sampledSimilarity(first, second):
    """
    Lightweight fallback similarity for very large responses.

    It avoids expensive full-sequence matching while still comparing actual
    content (not only response length), reducing false positives.
    """

    first, second = _toBytes(first), _toBytes(second)

    if first == second:
        return 1.0
    elif not first or not second:
        return float(first == second)

    firstLength, secondLength = len(first), len(second)
    ratio = 1.0 * min(firstLength, secondLength) / max(firstLength, secondLength)

    window = min(4096, firstLength, secondLength)
    if not window:
        return ratio

    similarity = 0.0
    positions = (0.0, 0.25, 0.5, 0.75, 1.0)

    for position in positions:
        firstStart = int(max(0, firstLength - window) * position)
        secondStart = int(max(0, secondLength - window) * position)

        firstChunk = first[firstStart:firstStart + window]
        secondChunk = second[secondStart:secondStart + window]

        similarity += (1.0 * sum(left == right for left, right in zip(firstChunk, secondChunk)) / window)

    similarity /= len(positions)

    # Favor actual content match while still accounting for size drift.
    return 0.7 * similarity + 0.3 * ratio

def _median(values):
    ordered = sorted(values)
    middle = len(ordered) // 2

    if len(ordered) % 2:
        return ordered[middle]
    else:
        return (ordered[middle - 1] + ordered[middle]) / 2.0

def _mad(values, center):
    """
    Median Absolute Deviation around the given center value.

    Used as a robust, outlier-resistant estimate of the natural noise level
    observed during the matchRatio calibration window.
    """

    if not values:
        return 0.0

    return _median([abs(value - center) for value in values])

def comparison(page, headers, code=None, getRatioValue=False, pageLength=None):
    if not isinstance(page, (six.text_type, six.binary_type, type(None))):
        logger.critical("got page of type %s; repr(page)[:200]=%s" % (type(page), repr(page)[:200]))

        try:
            page = b"".join(page)
        except:
            page = six.text_type(page)

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
    calibrationKey = hash((kb.pageTemplate, conf.textOnly, conf.titles))

    if kb.matchRatio is not None:
        kb.matchRatioCandidates = []
        kb.matchRatioCalibrationKey = None
    elif getattr(kb, "matchRatioCalibrationKey", None) != calibrationKey:
        kb.matchRatioCandidates = []
        kb.matchRatioJitter = None
        kb.matchRatioCalibrationKey = calibrationKey

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
            if threadData.lastPageTemplate != kb.pageTemplate:
                threadData.lastPageTemplateCleaned = removeDynamicContent(kb.pageTemplate)
                threadData.lastPageTemplate = kb.pageTemplate

            seqMatcher.set_seq1(threadData.lastPageTemplateCleaned)

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
                ratio = _sampledSimilarity(seqMatcher.a, page)
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

            try:
                seqMatcher.set_seq1(seq1)
                seqMatcher.set_seq2(seq2)
            except:
                seqMatcher.set_seq1(repr(seq1))
                seqMatcher.set_seq2(repr(seq2))

            if key in kb.cache.comparison:
                ratio = kb.cache.comparison[key]
            else:
                try:
                    try:
                        ratio = seqMatcher.quick_ratio() if not kb.heavilyDynamic else seqMatcher.ratio()
                    except (TypeError, MemoryError, SystemError):
                        ratio = seqMatcher.ratio()
                except:
                    ratio = 0.0

                ratio = round(ratio, 3)

            if key:
                kb.cache.comparison[key] = ratio

    # If the url is stable and we did not set yet the match ratio and the
    # current injected value changes the url page content
    if kb.matchRatio is None:
        if ratio >= LOWER_RATIO_BOUND and ratio <= UPPER_RATIO_BOUND:
            kb.matchRatioCandidates.append(ratio)
            kb.matchRatioCandidates = kb.matchRatioCandidates[-MATCH_RATIO_MAX_SAMPLES:]

            if len(kb.matchRatioCandidates) >= MATCH_RATIO_MIN_SAMPLES:
                kb.matchRatio = round(_median(kb.matchRatioCandidates), 3)
                kb.matchRatioJitter = round(_mad(kb.matchRatioCandidates, kb.matchRatio), 3)
                sampleCount = len(kb.matchRatioCandidates)
                kb.matchRatioCandidates = []
                kb.matchRatioCalibrationKey = None
                logger.debug("setting match ratio for current parameter to %.3f (median of %d samples, jitter=%.3f)" % (kb.matchRatio, sampleCount, kb.matchRatioJitter))

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
        # Adaptive tolerance: the static DIFF_TOLERANCE acts as a hard floor
        # for stable pages, while noisy targets get a wider band derived
        # from the observed jitter (MAD) captured during calibration.
        jitter = getattr(kb, "matchRatioJitter", None) or 0.0
        tolerance = max(DIFF_TOLERANCE, JITTER_TOLERANCE_MULTIPLIER * jitter)
        return (ratio - kb.matchRatio) > tolerance
