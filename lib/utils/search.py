#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re
import socket

from lib.core.common import getSafeExString
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import urlencode
from lib.core.convert import getBytes
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import HTTP_HEADER
from lib.core.enums import REDIRECTION
from lib.core.exception import SqlmapBaseException
from lib.core.settings import BING_REGEX
from lib.core.settings import DUCKDUCKGO_REGEX
from lib.core.settings import DUMMY_SEARCH_USER_AGENT
from lib.core.settings import GOOGLE_CONSENT_COOKIE
from lib.core.settings import GOOGLE_REGEX
from lib.core.settings import HTTP_ACCEPT_ENCODING_HEADER_VALUE
from lib.core.settings import UNICODE_ENCODING
from lib.request.basic import decodePage
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import urllib as _urllib
from thirdparty.socks import socks

def _fetch(url, headers, data=None):
    """
    Fetches and returns the (decoded) content of a search engine results page
    (or None in case of a connection issue)
    """

    retVal = None

    try:
        req = _urllib.request.Request(url, data=getBytes(data) if data else None, headers=headers)
        conn = _urllib.request.urlopen(req)

        requestMsg = "HTTP request:\n%s %s" % ("POST" if data else "GET", url)
        requestMsg += " %s" % _http_client.HTTPConnection._http_vsn_str
        logger.log(CUSTOM_LOGGING.TRAFFIC_OUT, requestMsg)

        page = conn.read()
        responseHeaders = conn.info()

        responseMsg = "HTTP response (%s - %d):\n" % (conn.msg, conn.code)
        if conf.verbose <= 4:
            responseMsg += getUnicode(responseHeaders, UNICODE_ENCODING)
        elif conf.verbose > 4:
            responseMsg += "%s\n%s\n" % (responseHeaders, page)
        logger.log(CUSTOM_LOGGING.TRAFFIC_IN, responseMsg)

        page = decodePage(page, responseHeaders.get(HTTP_HEADER.CONTENT_ENCODING), responseHeaders.get(HTTP_HEADER.CONTENT_TYPE))
        retVal = getUnicode(page)  # Note: if decodePage call fails (Issue #4202)
    except _urllib.error.HTTPError as ex:
        try:
            retVal = getUnicode(ex.read())
        except Exception:
            pass
    except (_urllib.error.URLError, _http_client.error, socket.error, socket.timeout, socks.ProxyError):
        pass

    return retVal

def _search(dork):
    """
    This method performs the effective search using the provided dork,
    trying the available search engines in order of (current) scraping
    reliability and returning the results of the first one that yields any
    (so that the failure of a single engine does not break the feature)
    """

    if not dork:
        return None

    retVal = []
    seen = set()

    requestHeaders = {
        HTTP_HEADER.USER_AGENT: dict(conf.httpHeaders).get(HTTP_HEADER.USER_AGENT, DUMMY_SEARCH_USER_AGENT),
        HTTP_HEADER.ACCEPT_ENCODING: HTTP_ACCEPT_ENCODING_HEADER_VALUE,
        HTTP_HEADER.COOKIE: GOOGLE_CONSENT_COOKIE,
    }

    gpage = conf.googlePage if conf.googlePage > 1 else 1
    logger.info("using search result page #%d" % gpage)

    encoded = urlencode(dork, convall=True)

    # Note: (name, url, POST data, regex, regex flags, match->link). Ordered by current scraping reliability; tried in turn until one yields results (DuckDuckGo currently being the only consistently scrapeable one)
    engines = (
        ("DuckDuckGo", "https://html.duckduckgo.com/html/", "q=%s&s=%d" % (encoded, (gpage - 1) * 30), DUCKDUCKGO_REGEX, re.I | re.S, lambda match: match.group(1).replace("&amp;", "&")),
        ("Bing", "https://www.bing.com/search?q=%s&first=%d" % (encoded, (gpage - 1) * 10 + 1), None, BING_REGEX, re.I | re.S, lambda match: match.group(1)),
        ("Google", "https://www.google.com/search?q=%s&num=100&hl=en&complete=0&safe=off&filter=0&btnG=Search&start=%d" % (encoded, (gpage - 1) * 100), None, GOOGLE_REGEX, re.I, lambda match: match.group(1) or match.group(2)),
    )

    for name, url, data, regex, flags, extract in engines:
        page = _fetch(url, requestHeaders, data)

        if not page:
            continue

        count = 0
        for match in re.finditer(regex, page, flags):
            link = _urllib.parse.unquote(extract(match))
            if link and link not in seen:
                seen.add(link)
                retVal.append(link)
                count += 1

        if count:
            logger.info("found %d usable link%s using %s" % (count, 's' if count != 1 else "", name))
            break  # Note: stop at the first engine that actually returns results (others are only fallbacks)

        # Note: switch proxy (if available) when an abuse/captcha page was served (instead of pointlessly falling through to the next engine from the same blocked IP)
        if conf.proxyList and (("detected unusual traffic" in page) or ("issue with the Tor Exit Node you are currently using" in page)):
            warnMsg = "%s has detected 'unusual' traffic from the used IP address" % name
            raise SqlmapBaseException(warnMsg)

    if not retVal:
        warnMsg = "no usable links found (search engines might be blocking the used IP address)"
        logger.critical(warnMsg)

    return retVal

@stackedmethod
def search(dork):
    pushValue(kb.choices.redirect)
    kb.choices.redirect = REDIRECTION.YES

    try:
        return _search(dork)
    except SqlmapBaseException as ex:
        if conf.proxyList:
            logger.critical(getSafeExString(ex))

            warnMsg = "changing proxy"
            logger.warning(warnMsg)

            conf.proxy = None

            setHTTPHandlers()
            return search(dork)
        else:
            raise

    finally:
        kb.choices.redirect = popValue()

def setHTTPHandlers():  # Cross-referenced function
    raise NotImplementedError
