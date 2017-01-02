#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import httplib
import re
import socket
import urllib
import urllib2

from lib.core.common import getSafeExString
from lib.core.common import getUnicode
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import readInput
from lib.core.common import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import HTTP_HEADER
from lib.core.enums import REDIRECTION
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import DUMMY_SEARCH_USER_AGENT
from lib.core.settings import DUCKDUCKGO_REGEX
from lib.core.settings import DISCONNECT_SEARCH_REGEX
from lib.core.settings import GOOGLE_REGEX
from lib.core.settings import HTTP_ACCEPT_ENCODING_HEADER_VALUE
from lib.core.settings import UNICODE_ENCODING
from lib.request.basic import decodePage
from thirdparty.socks import socks


def _search(dork):
    """
    This method performs the effective search on Google providing
    the google dork and the Google session cookie
    """

    if not dork:
        return None

    headers = {}

    headers[HTTP_HEADER.USER_AGENT] = dict(conf.httpHeaders).get(HTTP_HEADER.USER_AGENT, DUMMY_SEARCH_USER_AGENT)
    headers[HTTP_HEADER.ACCEPT_ENCODING] = HTTP_ACCEPT_ENCODING_HEADER_VALUE

    try:
        req = urllib2.Request("https://www.google.com/ncr", headers=headers)
        conn = urllib2.urlopen(req)
    except Exception, ex:
        errMsg = "unable to connect to Google ('%s')" % getSafeExString(ex)
        raise SqlmapConnectionException(errMsg)

    gpage = conf.googlePage if conf.googlePage > 1 else 1
    logger.info("using search result page #%d" % gpage)

    url = "https://www.google.com/search?"
    url += "q=%s&" % urlencode(dork, convall=True)
    url += "num=100&hl=en&complete=0&safe=off&filter=0&btnG=Search"
    url += "&start=%d" % ((gpage - 1) * 100)

    try:
        req = urllib2.Request(url, headers=headers)
        conn = urllib2.urlopen(req)

        requestMsg = "HTTP request:\nGET %s" % url
        requestMsg += " %s" % httplib.HTTPConnection._http_vsn_str
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
    except urllib2.HTTPError, e:
        try:
            page = e.read()
        except Exception, ex:
            warnMsg = "problem occurred while trying to get "
            warnMsg += "an error page information (%s)" % getSafeExString(ex)
            logger.critical(warnMsg)
            return None
    except (urllib2.URLError, httplib.error, socket.error, socket.timeout, socks.ProxyError):
        errMsg = "unable to connect to Google"
        raise SqlmapConnectionException(errMsg)

    retVal = [urllib.unquote(match.group(1) or match.group(2)) for match in re.finditer(GOOGLE_REGEX, page, re.I)]

    if not retVal and "detected unusual traffic" in page:
        warnMsg = "Google has detected 'unusual' traffic from "
        warnMsg += "used IP address disabling further searches"
        logger.warn(warnMsg)

    if not retVal:
        message = "no usable links found. What do you want to do?"
        message += "\n[1] (re)try with DuckDuckGo (default)"
        message += "\n[2] (re)try with Disconnect Search"
        message += "\n[3] quit"
        choice = readInput(message, default="1").strip().upper()

        if choice == "Q":
            raise SqlmapUserQuitException
        elif choice == "2":
            url = "https://search.disconnect.me/searchTerms/search?"
            url += "start=nav&option=Web"
            url += "&query=%s" % urlencode(dork, convall=True)
            url += "&ses=Google&location_option=US"
            url += "&nextDDG=%s" % urlencode("/search?q=%s&setmkt=en-US&setplang=en-us&setlang=en-us&first=%d&FORM=PORE" % (urlencode(dork, convall=True), (gpage - 1) * 10), convall=True)
            url += "&sa=N&showIcons=false&filterIcons=none&js_enabled=1"
            regex = DISCONNECT_SEARCH_REGEX
        else:
            url = "https://duckduckgo.com/d.js?"
            url += "q=%s&p=%d&s=100" % (urlencode(dork, convall=True), gpage)
            regex = DUCKDUCKGO_REGEX

        try:
            req = urllib2.Request(url, headers=headers)
            conn = urllib2.urlopen(req)

            requestMsg = "HTTP request:\nGET %s" % url
            requestMsg += " %s" % httplib.HTTPConnection._http_vsn_str
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
        except urllib2.HTTPError, e:
            try:
                page = e.read()
            except socket.timeout:
                warnMsg = "connection timed out while trying "
                warnMsg += "to get error page information (%d)" % e.code
                logger.critical(warnMsg)
                return None
        except:
            errMsg = "unable to connect"
            raise SqlmapConnectionException(errMsg)

        retVal = [urllib.unquote(match.group(1)) for match in re.finditer(regex, page, re.I | re.S)]

    return retVal

def search(dork):
    pushValue(kb.redirectChoice)
    kb.redirectChoice = REDIRECTION.YES

    try:
        return _search(dork)
    except SqlmapBaseException, ex:
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

def setHTTPHandlers():  # Cross-linked function
    raise NotImplementedError
