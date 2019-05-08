#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re
import socket

from lib.core.common import getSafeExString
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import readInput
from lib.core.common import urlencode
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import HTTP_HEADER
from lib.core.enums import REDIRECTION
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import BING_REGEX
from lib.core.settings import DUMMY_SEARCH_USER_AGENT
from lib.core.settings import DUCKDUCKGO_REGEX
from lib.core.settings import GOOGLE_REGEX
from lib.core.settings import HTTP_ACCEPT_ENCODING_HEADER_VALUE
from lib.core.settings import UNICODE_ENCODING
from lib.request.basic import decodePage
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import urllib as _urllib
from thirdparty.socks import socks

def _search(dork):
    """
    This method performs the effective search on Google providing
    the google dork and the Google session cookie
    """

    if not dork:
        return None

    data = None
    headers = {}

    headers[HTTP_HEADER.USER_AGENT] = dict(conf.httpHeaders).get(HTTP_HEADER.USER_AGENT, DUMMY_SEARCH_USER_AGENT)
    headers[HTTP_HEADER.ACCEPT_ENCODING] = HTTP_ACCEPT_ENCODING_HEADER_VALUE

    try:
        req = _urllib.request.Request("https://www.google.com/ncr", headers=headers)
        conn = _urllib.request.urlopen(req)
    except Exception as ex:
        errMsg = "unable to connect to Google ('%s')" % getSafeExString(ex)
        raise SqlmapConnectionException(errMsg)

    gpage = conf.googlePage if conf.googlePage > 1 else 1
    logger.info("using search result page #%d" % gpage)

    url = "https://www.google.com/search?"
    url += "q=%s&" % urlencode(dork, convall=True)
    url += "num=100&hl=en&complete=0&safe=off&filter=0&btnG=Search"
    url += "&start=%d" % ((gpage - 1) * 100)

    try:
        req = _urllib.request.Request(url, headers=headers)
        conn = _urllib.request.urlopen(req)

        requestMsg = "HTTP request:\nGET %s" % url
        requestMsg += " %s" % _http_client.HTTPConnection._http_vsn_str
        logger.log(CUSTOM_LOGGING.TRAFFIC_OUT, requestMsg)

        page = conn.read()
        code = conn.code
        status = conn.msg
        responseHeaders = conn.info()
        page = decodePage(page, responseHeaders.get("Content-Encoding"), responseHeaders.get("Content-Type"))

        responseMsg = "HTTP response (%s - %d):\n" % (status, code)

        if conf.verbose <= 4:
            responseMsg += getUnicode(responseHeaders, UNICODE_ENCODING)
        elif conf.verbose > 4:
            responseMsg += "%s\n%s\n" % (responseHeaders, page)

        logger.log(CUSTOM_LOGGING.TRAFFIC_IN, responseMsg)
    except _urllib.error.HTTPError as ex:
        try:
            page = ex.read()
        except Exception as _:
            warnMsg = "problem occurred while trying to get "
            warnMsg += "an error page information (%s)" % getSafeExString(_)
            logger.critical(warnMsg)
            return None
    except (_urllib.error.URLError, _http_client.error, socket.error, socket.timeout, socks.ProxyError):
        errMsg = "unable to connect to Google"
        raise SqlmapConnectionException(errMsg)

    retVal = [_urllib.parse.unquote(match.group(1) or match.group(2)) for match in re.finditer(GOOGLE_REGEX, page, re.I)]

    if not retVal and "detected unusual traffic" in page:
        warnMsg = "Google has detected 'unusual' traffic from "
        warnMsg += "used IP address disabling further searches"

        if conf.proxyList:
            raise SqlmapBaseException(warnMsg)
        else:
            logger.critical(warnMsg)

    if not retVal:
        message = "no usable links found. What do you want to do?"
        message += "\n[1] (re)try with DuckDuckGo (default)"
        message += "\n[2] (re)try with Bing"
        message += "\n[3] quit"
        choice = readInput(message, default='1')

        if choice == '3':
            raise SqlmapUserQuitException
        elif choice == '2':
            url = "https://www.bing.com/search?q=%s&first=%d" % (urlencode(dork, convall=True), (gpage - 1) * 10 + 1)
            regex = BING_REGEX
        else:
            url = "https://duckduckgo.com/html/"
            data = "q=%s&s=%d" % (urlencode(dork, convall=True), (gpage - 1) * 30)
            regex = DUCKDUCKGO_REGEX

        try:
            req = _urllib.request.Request(url, data=data, headers=headers)
            conn = _urllib.request.urlopen(req)

            requestMsg = "HTTP request:\nGET %s" % url
            requestMsg += " %s" % _http_client.HTTPConnection._http_vsn_str
            logger.log(CUSTOM_LOGGING.TRAFFIC_OUT, requestMsg)

            page = conn.read()
            code = conn.code
            status = conn.msg
            responseHeaders = conn.info()
            page = decodePage(page, responseHeaders.get("Content-Encoding"), responseHeaders.get("Content-Type"))

            responseMsg = "HTTP response (%s - %d):\n" % (status, code)

            if conf.verbose <= 4:
                responseMsg += getUnicode(responseHeaders, UNICODE_ENCODING)
            elif conf.verbose > 4:
                responseMsg += "%s\n%s\n" % (responseHeaders, page)

            logger.log(CUSTOM_LOGGING.TRAFFIC_IN, responseMsg)
        except _urllib.error.HTTPError as ex:
            try:
                page = ex.read()
                page = decodePage(page, ex.headers.get("Content-Encoding"), ex.headers.get("Content-Type"))
            except socket.timeout:
                warnMsg = "connection timed out while trying "
                warnMsg += "to get error page information (%d)" % ex.code
                logger.critical(warnMsg)
                return None
        except:
            errMsg = "unable to connect"
            raise SqlmapConnectionException(errMsg)

        retVal = [_urllib.parse.unquote(match.group(1).replace("&amp;", "&")) for match in re.finditer(regex, page, re.I | re.S)]

        if not retVal and "issue with the Tor Exit Node you are currently using" in page:
            warnMsg = "DuckDuckGo has detected 'unusual' traffic from "
            warnMsg += "used (Tor) IP address"

            if conf.proxyList:
                raise SqlmapBaseException(warnMsg)
            else:
                logger.critical(warnMsg)

    return retVal

@stackedmethod
def search(dork):
    pushValue(kb.redirectChoice)
    kb.redirectChoice = REDIRECTION.YES

    try:
        return _search(dork)
    except SqlmapBaseException as ex:
        if conf.proxyList:
            logger.critical(getSafeExString(ex))

            warnMsg = "changing proxy"
            logger.warn(warnMsg)

            conf.proxy = None

            setHTTPHandlers()
            return search(dork)
        else:
            raise
    finally:
        kb.redirectChoice = popValue()

def setHTTPHandlers():  # Cross-referenced function
    raise NotImplementedError
