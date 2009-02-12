#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""



import re

from lib.core.convert import md5hash
from lib.core.data import conf
from lib.core.data import logger


MATCH_RATIO = None


def comparison(page, headers=None, getSeqMatcher=False):
    global MATCH_RATIO

    regExpResults = None

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
        if conf.string in page:
            return True
        else:
            return False

    # Regular expression to match in page when the query is valid
    if conf.regexp:
        if re.search(conf.regexp, page, re.I | re.M):
            return True
        else:
            return False

    conf.seqMatcher.set_seq2(page)
    ratio = round(conf.seqMatcher.ratio(), 3)

    # If the url is stable and we did not set yet the match ratio and the
    # current injected value changes the url page content
    if MATCH_RATIO == None:
        if conf.md5hash != None and ratio < 1 and ratio > 0.6:
            logger.debug("setting match ratio to %.3f" % ratio)
            MATCH_RATIO = ratio
        elif conf.md5hash == None or ( conf.md5hash != None and ratio < 0.6 ):
            logger.debug("setting match ratio to default value 0.900")
            MATCH_RATIO = 0.900

    # If it has been requested to return the ratio and not a comparison
    # response
    if getSeqMatcher:
        return ratio

    # If the url is stable it returns True if the page has the same MD5
    # hash of the original one
    # NOTE: old implementation, it did not handle automatically the fact
    # that the url could be not stable (due to VIEWSTATE, counter, etc.)
    #elif conf.md5hash != None:
    #    return conf.md5hash == md5hash(page)

    # If the url is not stable it returns sequence matcher between the
    # first untouched HTTP response page content and this content
    elif ratio > MATCH_RATIO:
        return True
    else:
        return False
