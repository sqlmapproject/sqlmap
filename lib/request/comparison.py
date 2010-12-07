#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from difflib import SequenceMatcher

from lib.core.common import removeDynamicContent
from lib.core.common import wasLastRequestDBMSError
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.settings import CONSTANT_RATIO
from lib.core.settings import DIFF_TOLERANCE

def comparison(page, headers=None, getSeqMatcher=False, pageLength=None):
    if page is None and pageLength is None:
        return None

    regExpResults = None
    conf.seqMatcher.set_seq1(kb.pageTemplate)

    if page:
        # String to be excluded before calculating page hash
        if conf.eString and conf.eString in page:
            index              = page.index(conf.eString)
            length             = len(conf.eString)
            pageWithoutString  = page[:index]
            pageWithoutString += page[index+length:]
            page               = pageWithoutString

        # Regular expression matches to be excluded before calculating page hash
        if conf.eRegexp:
            regExpResults = re.findall(conf.eRegexp, page, re.I | re.M)

            if regExpResults:
                for regExpResult in regExpResults:
                    index              = page.index(regExpResult)
                    length             = len(regExpResult)
                    pageWithoutRegExp  = page[:index]
                    pageWithoutRegExp += page[index+length:]
                    page               = pageWithoutRegExp

        # String to match in page when the query is valid
        if conf.string:
            return conf.string in page

        # Regular expression to match in page when the query is valid
        if conf.regexp:
            return re.search(conf.regexp, page, re.I | re.M) is not None

        # In case of an DBMS error page return None
        if wasLastRequestDBMSError():
            return None

        # Dynamic content lines to be excluded before comparison
        if not kb.nullConnection and not conf.longestCommon:
            page = removeDynamicContent(page)
            conf.seqMatcher.set_seq1(removeDynamicContent(kb.pageTemplate))

        if not pageLength:
            pageLength = len(page)

    if kb.locks.seqLock:
        kb.locks.seqLock.acquire()

    if conf.longestCommon:
        (firstPage, secondPage) = (conf.seqMatcher.a, page)
        match = SequenceMatcher(None, firstPage, secondPage).find_longest_match(0, len(firstPage), 0, len(secondPage))
        ratio = round(SequenceMatcher(None, firstPage[match[0]:match[0]+match[2]], secondPage[match[1]:match[1]+match[2]]).ratio(), 3)

    elif not conf.eRegexp and not conf.eString and kb.nullConnection and pageLength:
        ratio = 1. * pageLength / len(conf.seqMatcher.a)

        if ratio > 1.:
            ratio = 1. / ratio
    else:
        conf.seqMatcher.set_seq2(page)
        ratio = round(conf.seqMatcher.real_quick_ratio(), 3)

    if kb.locks.seqLock:
        kb.locks.seqLock.release()

    # If the url is stable and we did not set yet the match ratio and the
    # current injected value changes the url page content
    if conf.matchRatio is None:
        if conf.thold:
            conf.matchRatio = conf.thold

        elif kb.pageStable and ratio > 0.6 and ratio < 1:
            conf.matchRatio = ratio
            logger.debug("setting match ratio for current parameter to %.3f" % conf.matchRatio)

        elif not kb.pageStable or ( kb.pageStable and ratio < 0.6 ):
            conf.matchRatio = CONSTANT_RATIO
            logger.debug("setting match ratio for current parameter to default value 0.900")

    # If it has been requested to return the ratio and not a comparison
    # response
    if getSeqMatcher:
        return ratio

    elif ratio == 1:
        return True

    elif conf.matchRatio is None:
        return None

    else:
        if conf.matchRatio == CONSTANT_RATIO or conf.thold:
            return ratio > conf.matchRatio
        else:
            return (ratio - conf.matchRatio) > DIFF_TOLERANCE
