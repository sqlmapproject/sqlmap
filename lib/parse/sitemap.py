#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import httplib
import re

from lib.core.common import readInput
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import SqlmapSyntaxException
from lib.request.connect import Connect as Request
from thirdparty.oset.pyoset import oset

abortedFlag = None

def parseSitemap(url, retVal=None):
    global abortedFlag

    if retVal is not None:
        logger.debug("parsing sitemap '%s'" % url)

    try:
        if retVal is None:
            abortedFlag = False
            retVal = oset()

        try:
            content = Request.getPage(url=url, raise404=True)[0] if not abortedFlag else ""
        except httplib.InvalidURL:
            errMsg = "invalid URL given for sitemap ('%s')" % url
            raise SqlmapSyntaxException, errMsg

        for match in re.finditer(r"<loc>\s*([^<]+)", content or ""):
            if abortedFlag:
                break
            url = match.group(1).strip()
            if url.endswith(".xml") and "sitemap" in url.lower():
                if kb.followSitemapRecursion is None:
                    message = "sitemap recursion detected. Do you want to follow? [y/N] "
                    kb.followSitemapRecursion = readInput(message, default='N', boolean=True)
                if kb.followSitemapRecursion:
                    parseSitemap(url, retVal)
            else:
                retVal.add(url)

    except KeyboardInterrupt:
        abortedFlag = True
        warnMsg = "user aborted during sitemap parsing. sqlmap "
        warnMsg += "will use partial list"
        logger.warn(warnMsg)

    return retVal
