#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
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

# a couple of packages used for baidu hacking
from bs4 import BeautifulSoup
import requests


def _remove_duplicate(links):
    if not links:
        return []

    tmplinks = map(lambda url: url[:url.find("?")], links)
    tmplinks = set(tmplinks)
    ret = []
    for link in links:
        for tmplink in tmplinks:
            if link.lower().find(tmplink.lower()) == 0:
                ret.append(link)
                tmplinks.remove(tmplink)
                break
    return ret

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

    if conf.baidu:
        try:
            req = urllib2.Request("http://www.baidu.com/", headers=headers)
            conn = urllib2.urlopen(req)
        except Exception, ex:
            errMsg = "unable to connect to Baidu ('%s')" % getSafeExString(ex)
            raise SqlmapConnectionException(errMsg)
    else:
        try:
            req = urllib2.Request("https://www.google.com/ncr", headers=headers)
            conn = urllib2.urlopen(req)
        except Exception, ex:
            errMsg = "unable to connect to Google ('%s')" % getSafeExString(ex)
            raise SqlmapConnectionException(errMsg)

    gpage = conf.googlePage if conf.googlePage > 1 else 1
    logger.info("using search result page #%d" % gpage)

    if conf.baidu:
        url = "http://www.baidu.com"
        url += "/s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&tn=baidu&rn=50"
        url += "&wd=%s" % urlencode(dork, convall=True)
        url += "&pn=%d" % ((gpage - 1) * 10)
    else:
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
        errMsg = "unable to connect to {}".format("Google" if not conf.baidu else "Baidu")
        raise SqlmapConnectionException(errMsg)
    retVal = []

    if conf.baidu:
        # baidu special processing
        content = BeautifulSoup(page, 'html.parser')
        results = content.find_all('div', class_='result c-container ')
        for result in results:
            baidu_link = result.find('a').attrs['href'];
            try:
                r = requests.get(baidu_link, timeout=10)
                if r and r.status_code == 200:
                    logger.info(r.url)
                    retVal.append(r.url)
            except Exception, e:
                logger.debug(e.message)
        retVal = _remove_duplicate(retVal)
    else:
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
