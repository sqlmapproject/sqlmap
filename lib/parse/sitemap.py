#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import readInput
from lib.core.convert import htmlUnescape
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import OrderedSet
from lib.core.exception import SqlmapSyntaxException
from lib.core.settings import MAX_SITEMAP_FETCHES
from lib.core.settings import MAX_SITEMAP_URLS
from lib.request.connect import Connect as Request
from thirdparty.six.moves import http_client as _http_client

abortedFlag = None

def parseSitemap(url, retVal=None, visited=None, urlFilter=None):
    """Parse a sitemap (recursively following nested sitemap indexes). 'urlFilter' - when given - must
    return True for a URL to be fetched or kept; it is enforced on the initial URL AND every nested
    sitemap fetched recursively, so a hostile sitemap index cannot pull the crawler out of scope."""

    global abortedFlag

    if retVal is not None:
        logger.debug("parsing sitemap '%s'" % url)

    try:
        if retVal is None:
            abortedFlag = False
            retVal = OrderedSet()
            visited = set()

        if url in visited or (urlFilter is not None and not urlFilter(url)):
            return retVal

        visited.add(url)

        if len(visited) > MAX_SITEMAP_FETCHES or len(retVal) >= MAX_SITEMAP_URLS:   # bound a hostile sitemap graph
            if not abortedFlag:                                                     # warn once on the False->True transition
                logger.warning("sitemap parsing stopped after reaching the fetch/URL limit. sqlmap will use partial list")
            abortedFlag = True
            return retVal

        try:
            content = Request.getPage(url=url, raise404=True)[0] if not abortedFlag else ""
        except _http_client.InvalidURL:
            errMsg = "invalid URL given for sitemap ('%s')" % url
            raise SqlmapSyntaxException(errMsg)

        if content:
            content = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)  # Note: strip (possibly multi-line) XML comments so commented-out <loc> entries aren't harvested

            for match in re.finditer(r"<\w*?loc[^>]*>\s*([^<]+)", content, re.I):
                if abortedFlag or len(retVal) >= MAX_SITEMAP_URLS:
                    break

                foundUrl = htmlUnescape(match.group(1).strip())

                # Basic validation to avoid junk
                if not foundUrl.startswith("http"):
                    continue

                if foundUrl.endswith(".xml") and "sitemap" in foundUrl.lower():
                    if kb.followSitemapRecursion is None:
                        message = "sitemap recursion detected. Do you want to follow? [y/N] "
                        kb.followSitemapRecursion = readInput(message, default='N', boolean=True)

                    if kb.followSitemapRecursion:
                        parseSitemap(foundUrl, retVal, visited, urlFilter)
                elif urlFilter is None or urlFilter(foundUrl):
                    retVal.add(foundUrl)

    except KeyboardInterrupt:
        abortedFlag = True
        warnMsg = "user aborted during sitemap parsing. sqlmap "
        warnMsg += "will use partial list"
        logger.warning(warnMsg)

    return retVal
