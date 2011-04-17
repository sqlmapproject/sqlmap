#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from difflib import SequenceMatcher

from lib.core.common import getFilteredPageContent
from lib.core.common import removeDynamicContent
from lib.core.common import wasLastRequestDBMSError
from lib.core.common import wasLastRequestHTTPError
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapNoneDataException
from lib.core.settings import DIFF_TOLERANCE
from lib.core.settings import MIN_RATIO
from lib.core.settings import MAX_RATIO
from lib.core.settings import LOWER_RATIO_BOUND
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.threads import getCurrentThreadData

def comparison(page, getRatioValue=False, pageLength=None):
    if page is None and pageLength is None:
        return None

    regExpResults = None

    seqMatcher = getCurrentThreadData().seqMatcher
    seqMatcher.set_seq1(kb.pageTemplate)

    if page:
        # String to match in page when the query is valid
        if conf.string:
            condition = conf.string in page
            return condition if not getRatioValue else (MAX_RATIO if condition else MIN_RATIO)

        # Regular expression to match in page when the query is valid
        if conf.regexp:
            condition = re.search(conf.regexp, page, re.I | re.M) is not None
            return condition if not getRatioValue else (MAX_RATIO if condition else MIN_RATIO)

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
            errMsg += "which prevents sqlmap from continuation. please rerun, "
            errMsg += "and if problem persists please turn off optimization switches"
            raise sqlmapNoneDataException, errMsg

        ratio = 1. * pageLength / len(seqMatcher.a)

        if ratio > 1.:
            ratio = 1. / ratio
    else:
        seqMatcher.set_seq1(getFilteredPageContent(seqMatcher.a, True) if conf.textOnly else seqMatcher.a)
        seqMatcher.set_seq2(getFilteredPageContent(page, True) if conf.textOnly else page)
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
