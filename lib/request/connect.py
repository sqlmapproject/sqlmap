#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import binascii
import inspect
import logging
import os
import random
import re
import socket
import string
import struct
import sys
import time
import traceback

try:
    import websocket
    from websocket import WebSocketException
except ImportError:
    class WebSocketException(Exception):
        pass

from lib.core.agent import agent
from lib.core.common import asciifyUrl
from lib.core.common import calculateDeltaSeconds
from lib.core.common import checkFile
from lib.core.common import checkSameHost
from lib.core.common import chunkSplitPostData
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import escapeJsonValue
from lib.core.common import evaluateCode
from lib.core.common import extractRegexResult
from lib.core.common import filterNone
from lib.core.common import findMultipartPostBoundary
from lib.core.common import getCurrentThreadData
from lib.core.common import getHeader
from lib.core.common import getHostHeader
from lib.core.common import getRequestHeader
from lib.core.common import getSafeExString
from lib.core.common import logHTTPTraffic
from lib.core.common import openFile
from lib.core.common import popValue
from lib.core.common import parseJson
from lib.core.common import pushValue
from lib.core.common import randomizeParameterValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import removeReflectiveValues
from lib.core.common import safeVariableNaming
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import stdev
from lib.core.common import unArrayizeValue
from lib.core.common import unsafeVariableNaming
from lib.core.common import urldecode
from lib.core.common import urlencode
from lib.core.common import wasLastResponseDelayed
from lib.core.compat import patchHeaders
from lib.core.compat import xrange
from lib.core.convert import encodeBase64
from lib.core.convert import getBytes
from lib.core.convert import getText
from lib.core.convert import getUnicode
from lib.core.data import cmdLineOptions
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import AttribDict
from lib.core.decorators import stackedmethod
from lib.core.dicts import POST_HINT_CONTENT_TYPES
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import AUTH_TYPE
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import HINT
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NULLCONNECTION
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.enums import POST_HINT
from lib.core.enums import REDIRECTION
from lib.core.enums import WEB_PLATFORM
from lib.core.exception import SqlmapCompressionException
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapSkipTargetException
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapTokenException
from lib.core.exception import SqlmapValueException
from lib.core.settings import ASTERISK_MARKER
from lib.core.settings import BOUNDARY_BACKSLASH_MARKER
from lib.core.settings import DEFAULT_CONTENT_TYPE
from lib.core.settings import DEFAULT_COOKIE_DELIMITER
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import DEFAULT_USER_AGENT
from lib.core.settings import EVALCODE_ENCODED_PREFIX
from lib.core.settings import HTTP_ACCEPT_ENCODING_HEADER_VALUE
from lib.core.settings import HTTP_ACCEPT_HEADER_VALUE
from lib.core.settings import IPS_WAF_CHECK_PAYLOAD
from lib.core.settings import IS_WIN
from lib.core.settings import JAVASCRIPT_HREF_REGEX
from lib.core.settings import LARGE_READ_TRIM_MARKER
from lib.core.settings import LIVE_COOKIES_TIMEOUT
from lib.core.settings import MAX_CONNECTION_READ_SIZE
from lib.core.settings import MAX_CONNECTIONS_REGEX
from lib.core.settings import MAX_CONNECTION_TOTAL_SIZE
from lib.core.settings import MAX_CONSECUTIVE_CONNECTION_ERRORS
from lib.core.settings import MAX_MURPHY_SLEEP_TIME
from lib.core.settings import META_REFRESH_REGEX
from lib.core.settings import MAX_TIME_RESPONSES
from lib.core.settings import MIN_TIME_RESPONSES
from lib.core.settings import PAYLOAD_DELIMITER
from lib.core.settings import PERMISSION_DENIED_REGEX
from lib.core.settings import PLAIN_TEXT_CONTENT_TYPE
from lib.core.settings import RANDOM_INTEGER_MARKER
from lib.core.settings import RANDOM_STRING_MARKER
from lib.core.settings import REPLACEMENT_MARKER
from lib.core.settings import TEXT_CONTENT_TYPE_REGEX
from lib.core.settings import UNENCODED_ORIGINAL_VALUE
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import URI_HTTP_HEADER
from lib.core.settings import WARN_TIME_STDEV
from lib.core.settings import WEBSOCKET_INITIAL_TIMEOUT
from lib.core.settings import YUGE_FACTOR
from lib.request.basic import decodePage
from lib.request.basic import forgeHeaders
from lib.request.basic import processResponse
from lib.request.comparison import comparison
from lib.request.direct import direct
from lib.request.methodrequest import MethodRequest
from lib.utils.safe2bin import safecharencode
from thirdparty import six
from thirdparty.odict import OrderedDict
from thirdparty.six import unichr as _unichr
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import urllib as _urllib
from thirdparty.socks.socks import ProxyError

class Connect(object):
    """
    This class defines methods used to perform HTTP requests
    """

    @staticmethod
    def _getPageProxy(**kwargs):
        try:
            if (len(inspect.stack()) > sys.getrecursionlimit() // 2):   # Note: https://github.com/sqlmapproject/sqlmap/issues/4525
                warnMsg = "unable to connect to the target URL"
                raise SqlmapConnectionException(warnMsg)
        except TypeError:
            pass

        try:
            return Connect.getPage(**kwargs)
        except RuntimeError:
            return None, None, None

    @staticmethod
    def _retryProxy(**kwargs):
        threadData = getCurrentThreadData()
        threadData.retriesCount += 1

        if conf.proxyList and threadData.retriesCount >= conf.retries and not kb.locks.handlers.locked():
            warnMsg = "changing proxy"
            logger.warn(warnMsg)

            conf.proxy = None
            threadData.retriesCount = 0

            setHTTPHandlers()

        if kb.testMode and kb.previousMethod == PAYLOAD.METHOD.TIME:
            # timed based payloads can cause web server unresponsiveness
            # if the injectable piece of code is some kind of JOIN-like query
            warnMsg = "most likely web server instance hasn't recovered yet "
            warnMsg += "from previous timed based payload. If the problem "
            warnMsg += "persists please wait for a few minutes and rerun "
            warnMsg += "without flag 'T' in option '--technique' "
            warnMsg += "(e.g. '--flush-session --technique=BEUS') or try to "
            warnMsg += "lower the value of option '--time-sec' (e.g. '--time-sec=2')"
            singleTimeWarnMessage(warnMsg)

        elif kb.originalPage is None:
            if conf.tor:
                warnMsg = "please make sure that you have "
                warnMsg += "Tor installed and running so "
                warnMsg += "you could successfully use "
                warnMsg += "switch '--tor' "
                if IS_WIN:
                    warnMsg += "(e.g. 'https://www.torproject.org/download/')"
                else:
                    warnMsg += "(e.g. 'https://help.ubuntu.com/community/Tor')"
            else:
                warnMsg = "if the problem persists please check that the provided "
                warnMsg += "target URL is reachable"

                items = []
                if not conf.randomAgent:
                    items.append("switch '--random-agent'")
                if not any((conf.proxy, conf.proxyFile, conf.tor)):
                    items.append("proxy switches ('--proxy', '--proxy-file'...)")
                if items:
                    warnMsg += ". In case that it is, "
                    warnMsg += "you can try to rerun with "
                    warnMsg += " and/or ".join(items)

            singleTimeWarnMessage(warnMsg)

        elif conf.threads > 1:
            warnMsg = "if the problem persists please try to lower "
            warnMsg += "the number of used threads (option '--threads')"
            singleTimeWarnMessage(warnMsg)

        kwargs['retrying'] = True
        return Connect._getPageProxy(**kwargs)

    @staticmethod
    def _connReadProxy(conn):
        retVal = b""

        if not kb.dnsMode and conn:
            headers = conn.info()
            if kb.pageCompress and headers and hasattr(headers, "getheader") and (headers.getheader(HTTP_HEADER.CONTENT_ENCODING, "").lower() in ("gzip", "deflate") or "text" not in headers.getheader(HTTP_HEADER.CONTENT_TYPE, "").lower()):
                retVal = conn.read(MAX_CONNECTION_TOTAL_SIZE)
                if len(retVal) == MAX_CONNECTION_TOTAL_SIZE:
                    warnMsg = "large compressed response detected. Disabling compression"
                    singleTimeWarnMessage(warnMsg)
                    kb.pageCompress = False
                    raise SqlmapCompressionException
            else:
                while True:
                    if not conn:
                        break
                    else:
                        try:
                            part = conn.read(MAX_CONNECTION_READ_SIZE)
                        except AssertionError:
                            part = b""

                    if len(part) == MAX_CONNECTION_READ_SIZE:
                        warnMsg = "large response detected. This could take a while"
                        singleTimeWarnMessage(warnMsg)
                        part = re.sub(getBytes(r"(?si)%s.+?%s" % (kb.chars.stop, kb.chars.start)), getBytes("%s%s%s" % (kb.chars.stop, LARGE_READ_TRIM_MARKER, kb.chars.start)), part)
                        retVal += part
                    else:
                        retVal += part
                        break

                    if len(retVal) > MAX_CONNECTION_TOTAL_SIZE:
                        warnMsg = "too large response detected. Automatically trimming it"
                        singleTimeWarnMessage(warnMsg)
                        break

        if conf.yuge:
            retVal = YUGE_FACTOR * retVal

        return retVal

    @staticmethod
    def getPage(**kwargs):
        """
        This method connects to the target URL or proxy and returns
        the target URL page content
        """

        if conf.offline:
            return None, None, None

        url = kwargs.get("url", None) or conf.url
        get = kwargs.get("get", None)
        post = kwargs.get("post", None)
        method = kwargs.get("method", None)
        cookie = kwargs.get("cookie", None)
        ua = kwargs.get("ua", None) or conf.agent
        referer = kwargs.get("referer", None) or conf.referer
        host = kwargs.get("host", None) or conf.host
        direct_ = kwargs.get("direct", False)
        multipart = kwargs.get("multipart", None)
        silent = kwargs.get("silent", False)
        raise404 = kwargs.get("raise404", True)
        timeout = kwargs.get("timeout", None) or conf.timeout
        auxHeaders = kwargs.get("auxHeaders", None)
        response = kwargs.get("response", False)
        ignoreTimeout = kwargs.get("ignoreTimeout", False) or kb.ignoreTimeout or conf.ignoreTimeouts
        refreshing = kwargs.get("refreshing", False)
        retrying = kwargs.get("retrying", False)
        crawling = kwargs.get("crawling", False)
        checking = kwargs.get("checking", False)
        skipRead = kwargs.get("skipRead", False)
        finalCode = kwargs.get("finalCode", False)
        chunked = kwargs.get("chunked", False) or conf.chunked

        start = time.time()

        if isinstance(conf.delay, (int, float)) and conf.delay > 0:
            time.sleep(conf.delay)

        threadData = getCurrentThreadData()
        with kb.locks.request:
            kb.requestCounter += 1
            threadData.lastRequestUID = kb.requestCounter

            if conf.proxyFreq:
                if kb.requestCounter % conf.proxyFreq == 1:
                    conf.proxy = None

                    warnMsg = "changing proxy"
                    logger.warn(warnMsg)

                    setHTTPHandlers()

        if conf.dummy or conf.murphyRate and randomInt() % conf.murphyRate == 0:
            if conf.murphyRate:
                time.sleep(randomInt() % (MAX_MURPHY_SLEEP_TIME + 1))

            page, headers, code = randomStr(int(randomInt()), alphabet=[_unichr(_) for _ in xrange(256)]), None, None if not conf.murphyRate else randomInt(3)

            threadData.lastPage = page
            threadData.lastCode = code

            return page, headers, code

        if conf.liveCookies:
            with kb.locks.liveCookies:
                if not checkFile(conf.liveCookies, raiseOnError=False) or os.path.getsize(conf.liveCookies) == 0:
                    warnMsg = "[%s] [WARNING] live cookies file '%s' is empty or non-existent. Waiting for timeout (%d seconds)" % (time.strftime("%X"), conf.liveCookies, LIVE_COOKIES_TIMEOUT)
                    dataToStdout(warnMsg)

                    valid = False
                    for _ in xrange(LIVE_COOKIES_TIMEOUT):
                        if checkFile(conf.liveCookies, raiseOnError=False) and os.path.getsize(conf.liveCookies) > 0:
                            valid = True
                            break
                        else:
                            dataToStdout('.')
                            time.sleep(1)

                    dataToStdout("\n")

                    if not valid:
                        errMsg = "problem occurred while loading cookies from file '%s'" % conf.liveCookies
                        raise SqlmapValueException(errMsg)

                cookie = openFile(conf.liveCookies).read().strip()
                cookie = re.sub(r"(?i)\ACookie:\s*", "", cookie)

        if multipart:
            post = multipart
        else:
            if not post:
                chunked = False

            elif chunked:
                post = _urllib.parse.unquote(post)
                post = chunkSplitPostData(post)

        webSocket = url.lower().startswith("ws")

        if not _urllib.parse.urlsplit(url).netloc:
            url = _urllib.parse.urljoin(conf.url, url)

        # flag to know if we are dealing with the same target host
        target = checkSameHost(url, conf.url)

        if not retrying:
            # Reset the number of connection retries
            threadData.retriesCount = 0

        # fix for known issue when urllib2 just skips the other part of provided
        # url splitted with space char while urlencoding it in the later phase
        url = url.replace(" ", "%20")

        if "://" not in url:
            url = "http://%s" % url

        conn = None
        page = None
        code = None
        status = None

        _ = _urllib.parse.urlsplit(url)
        requestMsg = u"HTTP request [#%d]:\r\n%s " % (threadData.lastRequestUID, method or (HTTPMETHOD.POST if post is not None else HTTPMETHOD.GET))
        requestMsg += getUnicode(("%s%s" % (_.path or "/", ("?%s" % _.query) if _.query else "")) if not any((refreshing, crawling, checking)) else url)
        responseMsg = u"HTTP response "
        requestHeaders = u""
        responseHeaders = None
        logHeaders = u""
        skipLogTraffic = False

        raise404 = raise404 and not kb.ignoreNotFound

        # support for non-latin (e.g. cyrillic) URLs as urllib/urllib2 doesn't
        # support those by default
        url = asciifyUrl(url)

        try:
            socket.setdefaulttimeout(timeout)

            if direct_:
                if '?' in url:
                    url, params = url.split('?', 1)
                    params = urlencode(params)
                    url = "%s?%s" % (url, params)

            elif any((refreshing, crawling, checking)):
                pass

            elif target:
                if conf.forceSSL:
                    url = re.sub(r"(?i)\A(http|ws):", r"\g<1>s:", url)
                    url = re.sub(r"(?i):80/", ":443/", url)

                if PLACE.GET in conf.parameters and not get:
                    get = conf.parameters[PLACE.GET]

                    if not conf.skipUrlEncode:
                        get = urlencode(get, limit=True)

                if get:
                    if '?' in url:
                        url = "%s%s%s" % (url, DEFAULT_GET_POST_DELIMITER, get)
                        requestMsg += "%s%s" % (DEFAULT_GET_POST_DELIMITER, get)
                    else:
                        url = "%s?%s" % (url, get)
                        requestMsg += "?%s" % get

                if PLACE.POST in conf.parameters and not post and method != HTTPMETHOD.GET:
                    post = conf.parameters[PLACE.POST]

            elif get:
                url = "%s?%s" % (url, get)
                requestMsg += "?%s" % get

            requestMsg += " %s" % _http_client.HTTPConnection._http_vsn_str

            # Prepare HTTP headers
            headers = forgeHeaders({HTTP_HEADER.COOKIE: cookie, HTTP_HEADER.USER_AGENT: ua, HTTP_HEADER.REFERER: referer, HTTP_HEADER.HOST: host}, base=None if target else {})

            if HTTP_HEADER.COOKIE in headers:
                cookie = headers[HTTP_HEADER.COOKIE]

            if kb.authHeader:
                headers[HTTP_HEADER.AUTHORIZATION] = kb.authHeader

            if kb.proxyAuthHeader:
                headers[HTTP_HEADER.PROXY_AUTHORIZATION] = kb.proxyAuthHeader

            if not conf.requestFile or not target:
                if not getHeader(headers, HTTP_HEADER.HOST):
                    headers[HTTP_HEADER.HOST] = getHostHeader(url)

                if not getHeader(headers, HTTP_HEADER.ACCEPT):
                    headers[HTTP_HEADER.ACCEPT] = HTTP_ACCEPT_HEADER_VALUE

                if not getHeader(headers, HTTP_HEADER.ACCEPT_ENCODING):
                    headers[HTTP_HEADER.ACCEPT_ENCODING] = HTTP_ACCEPT_ENCODING_HEADER_VALUE if kb.pageCompress else "identity"

            elif conf.requestFile and getHeader(headers, HTTP_HEADER.USER_AGENT) == DEFAULT_USER_AGENT:
                for header in headers:
                    if header.upper() == HTTP_HEADER.USER_AGENT.upper():
                        del headers[header]
                        break

            if post is not None and not multipart and not getHeader(headers, HTTP_HEADER.CONTENT_TYPE):
                headers[HTTP_HEADER.CONTENT_TYPE] = POST_HINT_CONTENT_TYPES.get(kb.postHint, DEFAULT_CONTENT_TYPE if unArrayizeValue(conf.base64Parameter) != HTTPMETHOD.POST else PLAIN_TEXT_CONTENT_TYPE)

            if headers.get(HTTP_HEADER.CONTENT_TYPE) == POST_HINT_CONTENT_TYPES[POST_HINT.MULTIPART]:
                warnMsg = "missing 'boundary parameter' in '%s' header. " % HTTP_HEADER.CONTENT_TYPE
                warnMsg += "Will try to reconstruct"
                singleTimeWarnMessage(warnMsg)

                boundary = findMultipartPostBoundary(conf.data)
                if boundary:
                    headers[HTTP_HEADER.CONTENT_TYPE] = "%s; boundary=%s" % (headers[HTTP_HEADER.CONTENT_TYPE], boundary)

            if conf.keepAlive:
                headers[HTTP_HEADER.CONNECTION] = "keep-alive"

            if chunked:
                headers[HTTP_HEADER.TRANSFER_ENCODING] = "chunked"

            if auxHeaders:
                headers = forgeHeaders(auxHeaders, headers)

            if kb.headersFile:
                content = openFile(kb.headersFile, "rb").read()
                for line in content.split("\n"):
                    line = getText(line.strip())
                    if ':' in line:
                        header, value = line.split(':', 1)
                        headers[header] = value

            if conf.localhost:
                headers[HTTP_HEADER.HOST] = "localhost"

            for key, value in list(headers.items()):
                del headers[key]
                if isinstance(value, six.string_types):
                    for char in (r"\r", r"\n"):
                        value = re.sub(r"(%s)([^ \t])" % char, r"\g<1>\t\g<2>", value)
                    headers[getBytes(key) if six.PY2 else key] = getBytes(value.strip("\r\n"))  # Note: Python3 has_header() expects non-bytes value

            if six.PY2:
                url = getBytes(url)  # Note: Python3 requires text while Python2 has problems when mixing text with binary POST

            if webSocket:
                ws = websocket.WebSocket()
                ws.settimeout(WEBSOCKET_INITIAL_TIMEOUT if kb.webSocketRecvCount is None else timeout)
                ws.connect(url, header=("%s: %s" % _ for _ in headers.items() if _[0] not in ("Host",)), cookie=cookie)  # WebSocket will add Host field of headers automatically
                ws.send(urldecode(post or ""))

                _page = []

                if kb.webSocketRecvCount is None:
                    while True:
                        try:
                            _page.append(ws.recv())
                        except websocket.WebSocketTimeoutException:
                            kb.webSocketRecvCount = len(_page)
                            break
                else:
                    for i in xrange(max(1, kb.webSocketRecvCount)):
                        _page.append(ws.recv())

                page = "\n".join(_page)

                ws.close()
                code = ws.status
                status = _http_client.responses[code]

                class _(dict):
                    pass

                responseHeaders = _(ws.getheaders())
                responseHeaders.headers = ["%s: %s\r\n" % (_[0].capitalize(), _[1]) for _ in responseHeaders.items()]

                requestHeaders += "\r\n".join(["%s: %s" % (getUnicode(key.capitalize() if hasattr(key, "capitalize") else key), getUnicode(value)) for (key, value) in responseHeaders.items()])
                requestMsg += "\r\n%s" % requestHeaders

                if post is not None:
                    requestMsg += "\r\n\r\n%s" % getUnicode(post)

                requestMsg += "\r\n"

                threadData.lastRequestMsg = requestMsg

                logger.log(CUSTOM_LOGGING.TRAFFIC_OUT, requestMsg)
            else:
                post = getBytes(post)

                if unArrayizeValue(conf.base64Parameter) == HTTPMETHOD.POST:
                    if kb.place != HTTPMETHOD.POST:
                        conf.data = getattr(conf.data, UNENCODED_ORIGINAL_VALUE, conf.data)
                    else:
                        post = urldecode(post, convall=True)
                        post = encodeBase64(post)

                if target and cmdLineOptions.method or method and method not in (HTTPMETHOD.GET, HTTPMETHOD.POST):
                    req = MethodRequest(url, post, headers)
                    req.set_method(cmdLineOptions.method or method)
                elif url is not None:
                    req = _urllib.request.Request(url, post, headers)
                else:
                    return None, None, None

                for function in kb.preprocessFunctions:
                    try:
                        function(req)
                    except Exception as ex:
                        errMsg = "error occurred while running preprocess "
                        errMsg += "function '%s' ('%s')" % (function.__name__, getSafeExString(ex))
                        raise SqlmapGenericException(errMsg)
                    else:
                        post, headers = req.data, req.headers

                requestHeaders += "\r\n".join(["%s: %s" % (getUnicode(key.capitalize() if hasattr(key, "capitalize") else key), getUnicode(value)) for (key, value) in req.header_items()])

                if not getRequestHeader(req, HTTP_HEADER.COOKIE) and conf.cj:
                    conf.cj._policy._now = conf.cj._now = int(time.time())
                    cookies = conf.cj._cookies_for_request(req)
                    requestHeaders += "\r\n%s" % ("Cookie: %s" % ";".join("%s=%s" % (getUnicode(cookie.name), getUnicode(cookie.value)) for cookie in cookies))

                if post is not None:
                    if not getRequestHeader(req, HTTP_HEADER.CONTENT_LENGTH) and not chunked:
                        requestHeaders += "\r\n%s: %d" % (string.capwords(HTTP_HEADER.CONTENT_LENGTH), len(post))

                if not getRequestHeader(req, HTTP_HEADER.CONNECTION):
                    requestHeaders += "\r\n%s: %s" % (HTTP_HEADER.CONNECTION, "close" if not conf.keepAlive else "keep-alive")

                requestMsg += "\r\n%s" % requestHeaders

                if post is not None:
                    requestMsg += "\r\n\r\n%s" % getUnicode(post)

                if not chunked:
                    requestMsg += "\r\n"

                if not multipart:
                    threadData.lastRequestMsg = requestMsg

                    logger.log(CUSTOM_LOGGING.TRAFFIC_OUT, requestMsg)

                if conf.cj:
                    for cookie in conf.cj:
                        if cookie.value is None:
                            cookie.value = ""
                        else:
                            for char in (r"\r", r"\n"):
                                cookie.value = re.sub(r"(%s)([^ \t])" % char, r"\g<1>\t\g<2>", cookie.value)

                conn = _urllib.request.urlopen(req)

                if not kb.authHeader and getRequestHeader(req, HTTP_HEADER.AUTHORIZATION) and (conf.authType or "").lower() == AUTH_TYPE.BASIC.lower():
                    kb.authHeader = getUnicode(getRequestHeader(req, HTTP_HEADER.AUTHORIZATION))

                if not kb.proxyAuthHeader and getRequestHeader(req, HTTP_HEADER.PROXY_AUTHORIZATION):
                    kb.proxyAuthHeader = getRequestHeader(req, HTTP_HEADER.PROXY_AUTHORIZATION)

                # Return response object
                if response:
                    return conn, None, None

                # Get HTTP response
                if hasattr(conn, "redurl"):
                    page = (threadData.lastRedirectMsg[1] if kb.choices.redirect == REDIRECTION.NO else Connect._connReadProxy(conn)) if not skipRead else None
                    skipLogTraffic = kb.choices.redirect == REDIRECTION.NO
                    code = conn.redcode if not finalCode else code
                else:
                    page = Connect._connReadProxy(conn) if not skipRead else None

                if conn:
                    code = (code or conn.code) if conn.code == kb.originalCode else conn.code  # do not override redirection code (for comparison purposes)
                    responseHeaders = conn.info()
                    responseHeaders[URI_HTTP_HEADER] = conn.geturl() if hasattr(conn, "geturl") else url

                    if hasattr(conn, "redurl"):
                        responseHeaders[HTTP_HEADER.LOCATION] = conn.redurl

                    responseHeaders = patchHeaders(responseHeaders)
                    kb.serverHeader = responseHeaders.get(HTTP_HEADER.SERVER, kb.serverHeader)
                else:
                    code = None
                    responseHeaders = {}

                page = decodePage(page, responseHeaders.get(HTTP_HEADER.CONTENT_ENCODING), responseHeaders.get(HTTP_HEADER.CONTENT_TYPE), percentDecode=not crawling)
                status = getUnicode(conn.msg) if conn and getattr(conn, "msg", None) else None

            kb.connErrorCounter = 0

            if not refreshing:
                refresh = responseHeaders.get(HTTP_HEADER.REFRESH, "").split("url=")[-1].strip()

                if extractRegexResult(META_REFRESH_REGEX, page):
                    refresh = extractRegexResult(META_REFRESH_REGEX, page)

                    debugMsg = "got HTML meta refresh header"
                    logger.debug(debugMsg)

                if not refresh:
                    refresh = extractRegexResult(JAVASCRIPT_HREF_REGEX, page)

                    if refresh:
                        debugMsg = "got Javascript redirect logic"
                        logger.debug(debugMsg)

                if refresh:
                    if kb.alwaysRefresh is None:
                        msg = "got a refresh intent "
                        msg += "(redirect like response common to login pages) to '%s'. " % refresh
                        msg += "Do you want to apply it from now on? [Y/n]"

                        kb.alwaysRefresh = readInput(msg, default='Y', boolean=True)

                    if kb.alwaysRefresh:
                        if re.search(r"\Ahttps?://", refresh, re.I):
                            url = refresh
                        else:
                            url = _urllib.parse.urljoin(url, refresh)

                        threadData.lastRedirectMsg = (threadData.lastRequestUID, page)
                        kwargs["refreshing"] = True
                        kwargs["url"] = url
                        kwargs["get"] = None
                        kwargs["post"] = None

                        try:
                            return Connect._getPageProxy(**kwargs)
                        except SqlmapSyntaxException:
                            pass

            # Explicit closing of connection object
            if conn and not conf.keepAlive:
                try:
                    if hasattr(conn.fp, '_sock'):
                        conn.fp._sock.close()
                    conn.close()
                except Exception as ex:
                    warnMsg = "problem occurred during connection closing ('%s')" % getSafeExString(ex)
                    logger.warn(warnMsg)

        except SqlmapConnectionException as ex:
            if conf.proxyList and not kb.threadException:
                warnMsg = "unable to connect to the target URL ('%s')" % getSafeExString(ex)
                logger.critical(warnMsg)
                threadData.retriesCount = conf.retries
                return Connect._retryProxy(**kwargs)
            else:
                raise

        except _urllib.error.HTTPError as ex:
            page = None
            responseHeaders = None

            if checking:
                return None, None, None

            try:
                page = ex.read() if not skipRead else None
                responseHeaders = ex.info()
                responseHeaders[URI_HTTP_HEADER] = ex.geturl()
                responseHeaders = patchHeaders(responseHeaders)
                page = decodePage(page, responseHeaders.get(HTTP_HEADER.CONTENT_ENCODING), responseHeaders.get(HTTP_HEADER.CONTENT_TYPE), percentDecode=not crawling)
            except socket.timeout:
                warnMsg = "connection timed out while trying "
                warnMsg += "to get error page information (%d)" % ex.code
                logger.warn(warnMsg)
                return None, None, None
            except KeyboardInterrupt:
                raise
            except:
                pass
            finally:
                page = getUnicode(page)

            code = ex.code
            status = getUnicode(getattr(ex, "reason", None) or getSafeExString(ex).split(": ", 1)[-1])

            kb.originalCode = kb.originalCode or code
            threadData.lastHTTPError = (threadData.lastRequestUID, code, status)
            kb.httpErrorCodes[code] = kb.httpErrorCodes.get(code, 0) + 1

            responseMsg += "[#%d] (%s %s):\r\n" % (threadData.lastRequestUID, code, status)

            if responseHeaders:
                logHeaders = "".join(getUnicode(responseHeaders.headers)).strip()

            logHTTPTraffic(requestMsg, "%s%s\r\n\r\n%s" % (responseMsg, logHeaders, (page or "")[:MAX_CONNECTION_READ_SIZE]), start, time.time())

            skipLogTraffic = True

            if conf.verbose <= 5:
                responseMsg += getUnicode(logHeaders)
            elif conf.verbose > 5:
                responseMsg += "%s\r\n\r\n%s" % (logHeaders, (page or "")[:MAX_CONNECTION_READ_SIZE])

            if not multipart:
                logger.log(CUSTOM_LOGGING.TRAFFIC_IN, responseMsg)

            if ex.code not in (conf.ignoreCode or []):
                if ex.code == _http_client.UNAUTHORIZED:
                    errMsg = "not authorized, try to provide right HTTP "
                    errMsg += "authentication type and valid credentials (%d). " % code
                    errMsg += "If this is intended, try to rerun by providing "
                    errMsg += "a valid value for option '--ignore-code'"
                    raise SqlmapConnectionException(errMsg)
                elif chunked and ex.code in (_http_client.METHOD_NOT_ALLOWED, _http_client.LENGTH_REQUIRED):
                    warnMsg = "turning off HTTP chunked transfer encoding "
                    warnMsg += "as it seems that the target site doesn't support it (%d)" % code
                    singleTimeWarnMessage(warnMsg)
                    conf.chunked = kwargs["chunked"] = False
                    return Connect.getPage(**kwargs)
                elif ex.code == _http_client.REQUEST_URI_TOO_LONG:
                    warnMsg = "request URI is marked as too long by the target. "
                    warnMsg += "you are advised to try a switch '--no-cast' and/or '--no-escape'"
                    singleTimeWarnMessage(warnMsg)
                elif ex.code == _http_client.NOT_FOUND:
                    if raise404:
                        errMsg = "page not found (%d)" % code
                        raise SqlmapConnectionException(errMsg)
                    else:
                        debugMsg = "page not found (%d)" % code
                        singleTimeLogMessage(debugMsg, logging.DEBUG)
                elif ex.code == _http_client.GATEWAY_TIMEOUT:
                    if ignoreTimeout:
                        return None if not conf.ignoreTimeouts else "", None, None
                    else:
                        warnMsg = "unable to connect to the target URL (%d - %s)" % (ex.code, _http_client.responses[ex.code])
                        if threadData.retriesCount < conf.retries and not kb.threadException:
                            warnMsg += ". sqlmap is going to retry the request"
                            logger.critical(warnMsg)
                            return Connect._retryProxy(**kwargs)
                        elif kb.testMode:
                            logger.critical(warnMsg)
                            return None, None, None
                        else:
                            raise SqlmapConnectionException(warnMsg)
                else:
                    debugMsg = "got HTTP error code: %d ('%s')" % (code, status)
                    logger.debug(debugMsg)

        except (_urllib.error.URLError, socket.error, socket.timeout, _http_client.HTTPException, struct.error, binascii.Error, ProxyError, SqlmapCompressionException, WebSocketException, TypeError, ValueError, OverflowError, AttributeError):
            tbMsg = traceback.format_exc()

            if conf.debug:
                dataToStdout(tbMsg)

            if checking:
                return None, None, None
            elif "AttributeError:" in tbMsg:
                if "WSAECONNREFUSED" in tbMsg:
                    return None, None, None
                else:
                    raise
            elif "no host given" in tbMsg:
                warnMsg = "invalid URL address used (%s)" % repr(url)
                raise SqlmapSyntaxException(warnMsg)
            elif "forcibly closed" in tbMsg or "Connection is already closed" in tbMsg:
                warnMsg = "connection was forcibly closed by the target URL"
            elif "timed out" in tbMsg:
                if kb.testMode and kb.testType not in (None, PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED):
                    singleTimeWarnMessage("there is a possibility that the target (or WAF/IPS) is dropping 'suspicious' requests")
                    kb.droppingRequests = True
                warnMsg = "connection timed out to the target URL"
            elif "Connection reset" in tbMsg:
                if not conf.disablePrecon:
                    singleTimeWarnMessage("turning off pre-connect mechanism because of connection reset(s)")
                    conf.disablePrecon = True

                if kb.testMode:
                    singleTimeWarnMessage("there is a possibility that the target (or WAF/IPS) is resetting 'suspicious' requests")
                    kb.droppingRequests = True
                warnMsg = "connection reset to the target URL"
            elif "URLError" in tbMsg or "error" in tbMsg:
                warnMsg = "unable to connect to the target URL"
                match = re.search(r"Errno \d+\] ([^>\n]+)", tbMsg)
                if match:
                    warnMsg += " ('%s')" % match.group(1).strip()
            elif "NTLM" in tbMsg:
                warnMsg = "there has been a problem with NTLM authentication"
            elif "Invalid header name" in tbMsg:  # (e.g. PostgreSQL ::Text payload)
                return None, None, None
            elif "BadStatusLine" in tbMsg:
                warnMsg = "connection dropped or unknown HTTP "
                warnMsg += "status code received"
                if not conf.agent and not conf.randomAgent:
                    warnMsg += ". Try to force the HTTP User-Agent "
                    warnMsg += "header with option '--user-agent' or switch '--random-agent'"
            elif "IncompleteRead" in tbMsg:
                warnMsg = "there was an incomplete read error while retrieving data "
                warnMsg += "from the target URL"
            elif "Handshake status" in tbMsg:
                status = re.search(r"Handshake status ([\d]{3})", tbMsg)
                errMsg = "websocket handshake status %s" % status.group(1) if status else "unknown"
                raise SqlmapConnectionException(errMsg)
            elif "SqlmapCompressionException" in tbMsg:
                warnMsg = "problems with response (de)compression"
                retrying = True
            else:
                warnMsg = "unable to connect to the target URL"

            if "BadStatusLine" not in tbMsg and any((conf.proxy, conf.tor)):
                warnMsg += " or proxy"

            if silent:
                return None, None, None

            with kb.locks.connError:
                kb.connErrorCounter += 1

                if kb.connErrorCounter >= MAX_CONSECUTIVE_CONNECTION_ERRORS and kb.choices.connError is None:
                    message = "there seems to be a continuous problem with connection to the target. "
                    message += "Are you sure that you want to continue? [y/N] "

                    kb.choices.connError = readInput(message, default='N', boolean=True)

                if kb.choices.connError is False:
                    raise SqlmapSkipTargetException

            if "forcibly closed" in tbMsg:
                logger.critical(warnMsg)
                return None, None, None
            elif ignoreTimeout and any(_ in tbMsg for _ in ("timed out", "IncompleteRead", "Interrupted system call")):
                return None if not conf.ignoreTimeouts else "", None, None
            elif threadData.retriesCount < conf.retries and not kb.threadException:
                warnMsg += ". sqlmap is going to retry the request"
                if not retrying:
                    warnMsg += "(s)"
                    logger.critical(warnMsg)
                else:
                    logger.debug(warnMsg)
                return Connect._retryProxy(**kwargs)
            elif kb.testMode or kb.multiThreadMode:
                logger.critical(warnMsg)
                return None, None, None
            else:
                raise SqlmapConnectionException(warnMsg)

        finally:
            if isinstance(page, six.binary_type):
                if HTTP_HEADER.CONTENT_TYPE in (responseHeaders or {}) and not re.search(TEXT_CONTENT_TYPE_REGEX, responseHeaders[HTTP_HEADER.CONTENT_TYPE]):
                    page = six.text_type(page, errors="ignore")
                else:
                    page = getUnicode(page)

            for function in kb.postprocessFunctions:
                try:
                    page, responseHeaders, code = function(page, responseHeaders, code)
                except Exception as ex:
                    errMsg = "error occurred while running postprocess "
                    errMsg += "function '%s' ('%s')" % (function.__name__, getSafeExString(ex))
                    raise SqlmapGenericException(errMsg)

            threadData.lastPage = page
            threadData.lastCode = code

            socket.setdefaulttimeout(conf.timeout)

        if conf.retryOn and re.search(conf.retryOn, page, re.I):
            if threadData.retriesCount < conf.retries:
                warnMsg = "forced retry of the request because of undesired page content"
                logger.warn(warnMsg)
                return Connect._retryProxy(**kwargs)

        processResponse(page, responseHeaders, code, status)

        if not skipLogTraffic:
            if conn and getattr(conn, "redurl", None):
                _ = _urllib.parse.urlsplit(conn.redurl)
                _ = ("%s%s" % (_.path or "/", ("?%s" % _.query) if _.query else ""))
                requestMsg = re.sub(r"(\n[A-Z]+ ).+?( HTTP/\d)", r"\g<1>%s\g<2>" % getUnicode(_).replace("\\", "\\\\"), requestMsg, 1)

                if kb.resendPostOnRedirect is False:
                    requestMsg = re.sub(r"(\[#\d+\]:\n)POST ", r"\g<1>GET ", requestMsg)
                    requestMsg = re.sub(r"(?i)Content-length: \d+\n", "", requestMsg)
                    requestMsg = re.sub(r"(?s)\n\n.+", "\n", requestMsg)

                responseMsg += "[#%d] (%s %s):\r\n" % (threadData.lastRequestUID, conn.code, status)
            elif "\n" not in responseMsg:
                responseMsg += "[#%d] (%s %s):\r\n" % (threadData.lastRequestUID, code, status)

            if responseHeaders:
                logHeaders = "".join(getUnicode(responseHeaders.headers)).strip()

            logHTTPTraffic(requestMsg, "%s%s\r\n\r\n%s" % (responseMsg, logHeaders, (page or "")[:MAX_CONNECTION_READ_SIZE]), start, time.time())

            if conf.verbose <= 5:
                responseMsg += getUnicode(logHeaders)
            elif conf.verbose > 5:
                responseMsg += "%s\r\n\r\n%s" % (logHeaders, (page or "")[:MAX_CONNECTION_READ_SIZE])

            if not multipart:
                logger.log(CUSTOM_LOGGING.TRAFFIC_IN, responseMsg)

        return page, responseHeaders, code

    @staticmethod
    @stackedmethod
    def queryPage(value=None, place=None, content=False, getRatioValue=False, silent=False, method=None, timeBasedCompare=False, noteResponseTime=True, auxHeaders=None, response=False, raise404=None, removeReflection=True, disableTampering=False, ignoreSecondOrder=False):
        """
        This method calls a function to get the target URL page content
        and returns its page ratio (0 <= ratio <= 1) or a boolean value
        representing False/True match in case of !getRatioValue
        """

        if conf.direct:
            return direct(value, content)

        get = None
        post = None
        cookie = None
        ua = None
        referer = None
        host = None
        page = None
        pageLength = None
        uri = None
        code = None

        if not place:
            place = kb.injection.place or PLACE.GET

        kb.place = place

        if not auxHeaders:
            auxHeaders = {}

        raise404 = place != PLACE.URI if raise404 is None else raise404
        method = method or conf.method

        postUrlEncode = kb.postUrlEncode

        value = agent.adjustLateValues(value)
        payload = agent.extractPayload(value)
        threadData = getCurrentThreadData()

        if conf.httpHeaders:
            headers = OrderedDict(conf.httpHeaders)
            contentType = max(headers[_] or "" if _.upper() == HTTP_HEADER.CONTENT_TYPE.upper() else "" for _ in headers) or None

            if (kb.postHint or conf.skipUrlEncode) and postUrlEncode:
                postUrlEncode = False
                conf.httpHeaders = [_ for _ in conf.httpHeaders if _[1] != contentType]
                contentType = POST_HINT_CONTENT_TYPES.get(kb.postHint, PLAIN_TEXT_CONTENT_TYPE)
                conf.httpHeaders.append((HTTP_HEADER.CONTENT_TYPE, contentType))

        if payload:
            delimiter = conf.paramDel or (DEFAULT_GET_POST_DELIMITER if place != PLACE.COOKIE else DEFAULT_COOKIE_DELIMITER)

            if not disableTampering and kb.tamperFunctions:
                for function in kb.tamperFunctions:
                    hints = {}

                    try:
                        payload = function(payload=payload, headers=auxHeaders, delimiter=delimiter, hints=hints)
                    except Exception as ex:
                        errMsg = "error occurred while running tamper "
                        errMsg += "function '%s' ('%s')" % (function.__name__, getSafeExString(ex))
                        raise SqlmapGenericException(errMsg)

                    if not isinstance(payload, six.string_types):
                        errMsg = "tamper function '%s' returns " % function.__name__
                        errMsg += "invalid payload type ('%s')" % type(payload)
                        raise SqlmapValueException(errMsg)

                value = agent.replacePayload(value, payload)

                if hints:
                    if HINT.APPEND in hints:
                        value = "%s%s%s" % (value, delimiter, hints[HINT.APPEND])

                    if HINT.PREPEND in hints:
                        if place == PLACE.URI:
                            match = re.search(r"\w+\s*=\s*%s" % PAYLOAD_DELIMITER, value) or re.search(r"[^?%s/]=\s*%s" % (re.escape(delimiter), PAYLOAD_DELIMITER), value)
                            if match:
                                value = value.replace(match.group(0), "%s%s%s" % (hints[HINT.PREPEND], delimiter, match.group(0)))
                        else:
                            value = "%s%s%s" % (hints[HINT.PREPEND], delimiter, value)

            logger.log(CUSTOM_LOGGING.PAYLOAD, safecharencode(payload.replace('\\', BOUNDARY_BACKSLASH_MARKER)).replace(BOUNDARY_BACKSLASH_MARKER, '\\'))

            if place == PLACE.CUSTOM_POST and kb.postHint:
                if kb.postHint in (POST_HINT.SOAP, POST_HINT.XML):
                    # payloads in SOAP/XML should have chars > and < replaced
                    # with their HTML encoded counterparts
                    payload = payload.replace('&', "&amp;").replace('>', "&gt;").replace('<', "&lt;").replace('"', "&quot;").replace("'", "&apos;")  # Reference: https://stackoverflow.com/a/1091953
                elif kb.postHint == POST_HINT.JSON:
                    payload = escapeJsonValue(payload)
                elif kb.postHint == POST_HINT.JSON_LIKE:
                    payload = payload.replace("'", REPLACEMENT_MARKER).replace('"', "'").replace(REPLACEMENT_MARKER, '"')
                    payload = escapeJsonValue(payload)
                    payload = payload.replace("'", REPLACEMENT_MARKER).replace('"', "'").replace(REPLACEMENT_MARKER, '"')
                value = agent.replacePayload(value, payload)
            else:
                # GET, POST, URI and Cookie payload needs to be thoroughly URL encoded
                if (place in (PLACE.GET, PLACE.URI, PLACE.COOKIE) or place == PLACE.CUSTOM_HEADER and value.split(',')[0].upper() == HTTP_HEADER.COOKIE.upper()) and not conf.skipUrlEncode or place in (PLACE.POST, PLACE.CUSTOM_POST) and postUrlEncode:
                    skip = False

                    if place == PLACE.COOKIE or place == PLACE.CUSTOM_HEADER and value.split(',')[0].upper() == HTTP_HEADER.COOKIE.upper():
                        if kb.choices.cookieEncode is None:
                            msg = "do you want to URL encode cookie values (implementation specific)? %s" % ("[Y/n]" if not conf.url.endswith(".aspx") else "[y/N]")  # Reference: https://support.microsoft.com/en-us/kb/313282
                            kb.choices.cookieEncode = readInput(msg, default='Y' if not conf.url.endswith(".aspx") else 'N', boolean=True)
                        if not kb.choices.cookieEncode:
                            skip = True

                    if not skip:
                        if place in (PLACE.POST, PLACE.CUSTOM_POST):  # potential problems in other cases (e.g. URL encoding of whole URI - including path)
                            value = urlencode(value, spaceplus=kb.postSpaceToPlus)
                        payload = urlencode(payload, safe='%', spaceplus=kb.postSpaceToPlus)
                        value = agent.replacePayload(value, payload)
                        postUrlEncode = False

            if conf.hpp:
                if not any(conf.url.lower().endswith(_.lower()) for _ in (WEB_PLATFORM.ASP, WEB_PLATFORM.ASPX)):
                    warnMsg = "HTTP parameter pollution should work only against "
                    warnMsg += "ASP(.NET) targets"
                    singleTimeWarnMessage(warnMsg)
                if place in (PLACE.GET, PLACE.POST):
                    _ = re.escape(PAYLOAD_DELIMITER)
                    match = re.search(r"(?P<name>\w+)=%s(?P<value>.+?)%s" % (_, _), value)
                    if match:
                        payload = match.group("value")

                        for splitter in (urlencode(' '), ' '):
                            if splitter in payload:
                                prefix, suffix = ("*/", "/*") if splitter == ' ' else (urlencode(_) for _ in ("*/", "/*"))
                                parts = payload.split(splitter)
                                parts[0] = "%s%s" % (parts[0], suffix)
                                parts[-1] = "%s%s=%s%s" % (DEFAULT_GET_POST_DELIMITER, match.group("name"), prefix, parts[-1])
                                for i in xrange(1, len(parts) - 1):
                                    parts[i] = "%s%s=%s%s%s" % (DEFAULT_GET_POST_DELIMITER, match.group("name"), prefix, parts[i], suffix)
                                payload = "".join(parts)

                        for splitter in (urlencode(','), ','):
                            payload = payload.replace(splitter, "%s%s=" % (DEFAULT_GET_POST_DELIMITER, match.group("name")))

                        value = agent.replacePayload(value, payload)
                else:
                    warnMsg = "HTTP parameter pollution works only with regular "
                    warnMsg += "GET and POST parameters"
                    singleTimeWarnMessage(warnMsg)

        if place:
            value = agent.removePayloadDelimiters(value)

        if PLACE.GET in conf.parameters:
            get = conf.parameters[PLACE.GET] if place != PLACE.GET or not value else value
        elif place == PLACE.GET:  # Note: for (e.g.) checkWaf() when there are no GET parameters
            get = value

        if PLACE.POST in conf.parameters:
            post = conf.parameters[PLACE.POST] if place != PLACE.POST or not value else value
        elif place == PLACE.POST:
            post = value

        if PLACE.CUSTOM_POST in conf.parameters:
            post = conf.parameters[PLACE.CUSTOM_POST].replace(kb.customInjectionMark, "") if place != PLACE.CUSTOM_POST or not value else value
            post = post.replace(ASTERISK_MARKER, '*') if post else post

        if PLACE.COOKIE in conf.parameters:
            cookie = conf.parameters[PLACE.COOKIE] if place != PLACE.COOKIE or not value else value

        if PLACE.USER_AGENT in conf.parameters:
            ua = conf.parameters[PLACE.USER_AGENT] if place != PLACE.USER_AGENT or not value else value

        if PLACE.REFERER in conf.parameters:
            referer = conf.parameters[PLACE.REFERER] if place != PLACE.REFERER or not value else value

        if PLACE.HOST in conf.parameters:
            host = conf.parameters[PLACE.HOST] if place != PLACE.HOST or not value else value

        if PLACE.URI in conf.parameters:
            uri = conf.url if place != PLACE.URI or not value else value
        else:
            uri = conf.url

        if value and place == PLACE.CUSTOM_HEADER:
            if value.split(',')[0].capitalize() == PLACE.COOKIE:
                cookie = value.split(',', 1)[-1]
            else:
                auxHeaders[value.split(',')[0]] = value.split(',', 1)[-1]

        if conf.csrfToken:
            token = AttribDict()

            def _adjustParameter(paramString, parameter, newValue):
                retVal = paramString

                if urlencode(parameter) in paramString:
                    parameter = urlencode(parameter)

                match = re.search(r"%s=[^&]*" % re.escape(parameter), paramString, re.I)
                if match:
                    retVal = re.sub(r"(?i)%s" % re.escape(match.group(0)), ("%s=%s" % (parameter, newValue)).replace('\\', r'\\'), paramString)
                else:
                    match = re.search(r"(%s[\"']:[\"'])([^\"']+)" % re.escape(parameter), paramString, re.I)
                    if match:
                        retVal = re.sub(r"(?i)%s" % re.escape(match.group(0)), "%s%s" % (match.group(1), newValue), paramString)

                return retVal

            for attempt in xrange(conf.csrfRetries + 1):
                if token:
                    break

                if attempt > 0:
                    warnMsg = "unable to find anti-CSRF token '%s' at '%s'" % (conf.csrfToken._original, conf.csrfUrl or conf.url)
                    warnMsg += ". sqlmap is going to retry the request"
                    logger.warn(warnMsg)

                page, headers, code = Connect.getPage(url=conf.csrfUrl or conf.url, data=conf.data if conf.csrfUrl == conf.url else None, method=conf.csrfMethod or (conf.method if conf.csrfUrl == conf.url else None), cookie=conf.parameters.get(PLACE.COOKIE), direct=True, silent=True, ua=conf.parameters.get(PLACE.USER_AGENT), referer=conf.parameters.get(PLACE.REFERER), host=conf.parameters.get(PLACE.HOST))
                page = urldecode(page)  # for anti-CSRF tokens with special characters in their name (e.g. 'foo:bar=...')

                match = re.search(r"(?i)<input[^>]+\bname=[\"']?(?P<name>%s)\b[^>]*\bvalue=[\"']?(?P<value>[^>'\"]*)" % conf.csrfToken, page or "", re.I)

                if not match:
                    match = re.search(r"(?i)<input[^>]+\bvalue=[\"']?(?P<value>[^>'\"]*)[\"']?[^>]*\bname=[\"']?(?P<name>%s)\b" % conf.csrfToken, page or "", re.I)

                    if not match:
                        match = re.search(r"(?P<name>%s)[\"']:[\"'](?P<value>[^\"']+)" % conf.csrfToken, page or "", re.I)

                        if not match:
                            match = re.search(r"\b(?P<name>%s)\s*[:=]\s*(?P<value>\w+)" % conf.csrfToken, getUnicode(headers), re.I)

                            if not match:
                                match = re.search(r"\b(?P<name>%s)\s*=\s*['\"]?(?P<value>[^;'\"]+)" % conf.csrfToken, page or "", re.I)

                                if not match:
                                    match = re.search(r"<meta\s+name=[\"']?(?P<name>%s)[\"']?[^>]+\b(value|content)=[\"']?(?P<value>[^>\"']+)" % conf.csrfToken, page or "", re.I)

                if match:
                    token.name, token.value = match.group("name"), match.group("value")

                    match = re.search(r"String\.fromCharCode\(([\d+, ]+)\)", token.value)
                    if match:
                        token.value = "".join(_unichr(int(_)) for _ in match.group(1).replace(' ', "").split(','))

                if not token:
                    if conf.csrfUrl and conf.csrfToken and conf.csrfUrl != conf.url and code == _http_client.OK:
                        if headers and PLAIN_TEXT_CONTENT_TYPE in headers.get(HTTP_HEADER.CONTENT_TYPE, ""):
                            token.name = conf.csrfToken
                            token.value = page

                    if not token and conf.cj and any(re.search(conf.csrfToken, _.name, re.I) for _ in conf.cj):
                        for _ in conf.cj:
                            if re.search(conf.csrfToken, _.name, re.I):
                                token.name, token.value = _.name, _.value
                                if not any(re.search(conf.csrfToken, ' '.join(_), re.I) for _ in (conf.paramDict.get(PLACE.GET, {}), conf.paramDict.get(PLACE.POST, {}))):
                                    if post:
                                        post = "%s%s%s=%s" % (post, conf.paramDel or DEFAULT_GET_POST_DELIMITER, token.name, token.value)
                                    elif get:
                                        get = "%s%s%s=%s" % (get, conf.paramDel or DEFAULT_GET_POST_DELIMITER, token.name, token.value)
                                    else:
                                        get = "%s=%s" % (token.name, token.value)
                                break

            if not token:
                errMsg = "anti-CSRF token '%s' can't be found at '%s'" % (conf.csrfToken._original, conf.csrfUrl or conf.url)
                if not conf.csrfUrl:
                    errMsg += ". You can try to rerun by providing "
                    errMsg += "a valid value for option '--csrf-url'"
                raise SqlmapTokenException(errMsg)

            if token:
                token.value = token.value.strip("'\"")

                for candidate in (PLACE.GET, PLACE.POST, PLACE.CUSTOM_POST, PLACE.URI):
                    if candidate in conf.parameters:
                        if candidate == PLACE.URI and uri:
                            uri = _adjustParameter(uri, token.name, token.value)
                        elif candidate == PLACE.GET and get:
                            get = _adjustParameter(get, token.name, token.value)
                        elif candidate in (PLACE.POST, PLACE.CUSTOM_POST) and post:
                            post = _adjustParameter(post, token.name, token.value)

                for i in xrange(len(conf.httpHeaders)):
                    if conf.httpHeaders[i][0].lower() == token.name.lower():
                        conf.httpHeaders[i] = (conf.httpHeaders[i][0], token.value)

        if conf.rParam:
            def _randomizeParameter(paramString, randomParameter):
                retVal = paramString
                match = re.search(r"(\A|\b)%s=(?P<value>[^&;]*)" % re.escape(randomParameter), paramString)
                if match:
                    origValue = match.group("value")
                    newValue = randomizeParameterValue(origValue) if randomParameter not in kb.randomPool else random.sample(kb.randomPool[randomParameter], 1)[0]
                    retVal = re.sub(r"(\A|\b)%s=[^&;]*" % re.escape(randomParameter), "%s=%s" % (randomParameter, newValue), paramString)
                else:
                    match = re.search(r"(\A|\b)(%s\b[^\w]+)(?P<value>\w+)" % re.escape(randomParameter), paramString)
                    if match:
                        origValue = match.group("value")
                        newValue = randomizeParameterValue(origValue) if randomParameter not in kb.randomPool else random.sample(kb.randomPool[randomParameter], 1)[0]
                        retVal = paramString.replace(match.group(0), "%s%s" % (match.group(2), newValue))
                return retVal

            for randomParameter in conf.rParam:
                for item in (PLACE.GET, PLACE.POST, PLACE.COOKIE, PLACE.URI, PLACE.CUSTOM_POST):
                    if item in conf.parameters:
                        if item == PLACE.GET and get:
                            get = _randomizeParameter(get, randomParameter)
                        elif item in (PLACE.POST, PLACE.CUSTOM_POST) and post:
                            post = _randomizeParameter(post, randomParameter)
                        elif item == PLACE.COOKIE and cookie:
                            cookie = _randomizeParameter(cookie, randomParameter)
                        elif item == PLACE.URI and uri:
                            uri = _randomizeParameter(uri, randomParameter)

        if conf.evalCode:
            delimiter = conf.paramDel or DEFAULT_GET_POST_DELIMITER
            variables = {"uri": uri, "lastPage": threadData.lastPage, "_locals": locals(), "cookie": cookie}
            originals = {}

            if not get and PLACE.URI in conf.parameters:
                query = _urllib.parse.urlsplit(uri).query or ""
            else:
                query = None

            for item in filterNone((get, post if not kb.postHint else None, query)):
                for part in item.split(delimiter):
                    if '=' in part:
                        name, value = part.split('=', 1)
                        name = name.strip()
                        if safeVariableNaming(name) != name:
                            conf.evalCode = re.sub(r"\b%s\b" % re.escape(name), safeVariableNaming(name), conf.evalCode)
                            name = safeVariableNaming(name)
                        value = urldecode(value, convall=True, spaceplus=(item == post and kb.postSpaceToPlus))
                        variables[name] = value

            if post and kb.postHint in (POST_HINT.JSON, POST_HINT.JSON_LIKE):
                for name, value in (parseJson(post) or {}).items():
                    if safeVariableNaming(name) != name:
                        conf.evalCode = re.sub(r"\b%s\b" % re.escape(name), safeVariableNaming(name), conf.evalCode)
                        name = safeVariableNaming(name)
                    variables[name] = value

            if cookie:
                for part in cookie.split(conf.cookieDel or DEFAULT_COOKIE_DELIMITER):
                    if '=' in part:
                        name, value = part.split('=', 1)
                        name = name.strip()
                        if safeVariableNaming(name) != name:
                            conf.evalCode = re.sub(r"\b%s\b" % re.escape(name), safeVariableNaming(name), conf.evalCode)
                            name = safeVariableNaming(name)
                        value = urldecode(value, convall=True)
                        variables[name] = value

            while True:
                try:
                    compile(getBytes(re.sub(r"\s*;\s*", "\n", conf.evalCode)), "", "exec")
                except SyntaxError as ex:
                    if ex.text:
                        original = replacement = ex.text.strip()

                        if '=' in original:
                            name, value = original.split('=', 1)
                            name = name.strip()
                            if safeVariableNaming(name) != name:
                                replacement = re.sub(r"\b%s\b" % re.escape(name), safeVariableNaming(name), replacement)
                        else:
                            for _ in re.findall(r"[A-Za-z_]+", original)[::-1]:
                                if safeVariableNaming(_) != _:
                                    replacement = replacement.replace(_, safeVariableNaming(_))
                                    break

                        if original == replacement:
                            conf.evalCode = conf.evalCode.replace(EVALCODE_ENCODED_PREFIX, "")
                            break
                        else:
                            conf.evalCode = conf.evalCode.replace(getUnicode(ex.text.strip(), UNICODE_ENCODING), replacement)
                    else:
                        break
                else:
                    break

            originals.update(variables)
            evaluateCode(conf.evalCode, variables)

            for variable in list(variables.keys()):
                if unsafeVariableNaming(variable) != variable:
                    value = variables[variable]
                    del variables[variable]
                    variables[unsafeVariableNaming(variable)] = value

            uri = variables["uri"]
            cookie = variables["cookie"]

            for name, value in variables.items():
                if name != "__builtins__" and originals.get(name, "") != value:
                    if isinstance(value, (int, float, six.string_types, six.binary_type)):
                        found = False
                        value = getUnicode(value, UNICODE_ENCODING)

                        if kb.postHint == POST_HINT.MULTIPART:
                            boundary = "--%s" % re.search(r"boundary=([^\s]+)", contentType).group(1)
                            if boundary:
                                parts = post.split(boundary)
                                match = re.search(r'\bname="%s"' % re.escape(name), post)
                                if not match and parts:
                                    parts.insert(2, parts[1])
                                    parts[2] = re.sub(r'\bname="[^"]+".*', 'name="%s"' % re.escape(name), parts[2])
                                for i in xrange(len(parts)):
                                    part = parts[i]
                                    if re.search(r'\bname="%s"' % re.escape(name), part):
                                        match = re.search(r"(?s)\A.+?\r?\n\r?\n", part)
                                        if match:
                                            found = True
                                            first = match.group(0)
                                            second = part[len(first):]
                                            second = re.sub(r"(?s).+?(\r?\n?\-*\Z)", r"%s\g<1>" % re.escape(value), second)
                                            parts[i] = "%s%s" % (first, second)
                                post = boundary.join(parts)

                        elif kb.postHint and re.search(r"\b%s\b" % re.escape(name), post or ""):
                            if kb.postHint in (POST_HINT.XML, POST_HINT.SOAP):
                                if re.search(r"<%s\b" % re.escape(name), post):
                                    found = True
                                    post = re.sub(r"(?s)(<%s\b[^>]*>)(.*?)(</%s)" % (re.escape(name), re.escape(name)), r"\g<1>%s\g<3>" % value.replace('\\', r'\\'), post)
                                elif re.search(r"\b%s>" % re.escape(name), post):
                                    found = True
                                    post = re.sub(r"(?s)(\b%s>)(.*?)(</[^<]*\b%s>)" % (re.escape(name), re.escape(name)), r"\g<1>%s\g<3>" % value.replace('\\', r'\\'), post)

                            elif kb.postHint in (POST_HINT.JSON, POST_HINT.JSON_LIKE):
                                match = re.search(r"['\"]%s['\"]:" % re.escape(name), post)
                                if match:
                                    quote = match.group(0)[0]
                                    post = post.replace("\\%s" % quote, BOUNDARY_BACKSLASH_MARKER)
                                    match = re.search(r"(%s%s%s:\s*)(\d+|%s[^%s]*%s)" % (quote, re.escape(name), quote, quote, quote, quote), post)
                                    if match:
                                        found = True
                                        post = post.replace(match.group(0), "%s%s" % (match.group(1), value if value.isdigit() else "%s%s%s" % (match.group(0)[0], value, match.group(0)[0])))
                                    post = post.replace(BOUNDARY_BACKSLASH_MARKER, "\\%s" % quote)

                            regex = r"\b(%s)\b([^\w]+)(\w+)" % re.escape(name)
                            if not found and re.search(regex, (post or "")):
                                found = True
                                post = re.sub(regex, r"\g<1>\g<2>%s" % value.replace('\\', r'\\'), post)

                        regex = r"((\A|%s)%s=).+?(%s|\Z)" % (re.escape(delimiter), re.escape(name), re.escape(delimiter))
                        if not found and re.search(regex, (post or "")):
                            found = True
                            post = re.sub(regex, r"\g<1>%s\g<3>" % value.replace('\\', r'\\'), post)

                        if re.search(regex, (get or "")):
                            found = True
                            get = re.sub(regex, r"\g<1>%s\g<3>" % value.replace('\\', r'\\'), get)

                        if re.search(regex, (query or "")):
                            found = True
                            uri = re.sub(regex.replace(r"\A", r"\?"), r"\g<1>%s\g<3>" % value.replace('\\', r'\\'), uri)

                        regex = r"((\A|%s\s*)%s=).+?(%s|\Z)" % (re.escape(conf.cookieDel or DEFAULT_COOKIE_DELIMITER), re.escape(name), re.escape(conf.cookieDel or DEFAULT_COOKIE_DELIMITER))
                        if re.search(regex, (cookie or "")):
                            found = True
                            cookie = re.sub(regex, r"\g<1>%s\g<3>" % value.replace('\\', r'\\'), cookie)

                        if not found:
                            if post is not None:
                                if kb.postHint in (POST_HINT.JSON, POST_HINT.JSON_LIKE):
                                    match = re.search(r"['\"]", post)
                                    if match:
                                        quote = match.group(0)
                                        post = re.sub(r"\}\Z", "%s%s}" % (',' if re.search(r"\w", post) else "", "%s%s%s:%s" % (quote, name, quote, value if value.isdigit() else "%s%s%s" % (quote, value, quote))), post)
                                else:
                                    post += "%s%s=%s" % (delimiter, name, value)
                            elif get is not None:
                                get += "%s%s=%s" % (delimiter, name, value)
                            elif cookie is not None:
                                cookie += "%s%s=%s" % (conf.cookieDel or DEFAULT_COOKIE_DELIMITER, name, value)

        if not conf.skipUrlEncode:
            get = urlencode(get, limit=True)

        if post is not None:
            if place not in (PLACE.POST, PLACE.CUSTOM_POST) and hasattr(post, UNENCODED_ORIGINAL_VALUE):
                post = getattr(post, UNENCODED_ORIGINAL_VALUE)
            elif postUrlEncode:
                post = urlencode(post, spaceplus=kb.postSpaceToPlus)

        if timeBasedCompare and not conf.disableStats:
            if len(kb.responseTimes.get(kb.responseTimeMode, [])) < MIN_TIME_RESPONSES:
                clearConsoleLine()

                kb.responseTimes.setdefault(kb.responseTimeMode, [])

                if conf.tor:
                    warnMsg = "it's highly recommended to avoid usage of switch '--tor' for "
                    warnMsg += "time-based injections because of inherent high latency time"
                    singleTimeWarnMessage(warnMsg)

                warnMsg = "[%s] [WARNING] %stime-based comparison requires " % (time.strftime("%X"), "(case) " if kb.responseTimeMode else "")
                warnMsg += "%s statistical model, please wait" % ("larger" if len(kb.responseTimes) == 1 else "reset of")
                dataToStdout(warnMsg)

                while len(kb.responseTimes[kb.responseTimeMode]) < MIN_TIME_RESPONSES:
                    value = kb.responseTimePayload.replace(RANDOM_INTEGER_MARKER, str(randomInt(6))).replace(RANDOM_STRING_MARKER, randomStr()) if kb.responseTimePayload else kb.responseTimePayload
                    Connect.queryPage(value=value, content=True, raise404=False)
                    dataToStdout('.')

                dataToStdout(" (done)\n")

            elif not kb.testMode:
                warnMsg = "it is very important to not stress the network connection "
                warnMsg += "during usage of time-based payloads to prevent potential "
                warnMsg += "disruptions "
                singleTimeWarnMessage(warnMsg)

            if not kb.laggingChecked:
                kb.laggingChecked = True

                deviation = stdev(kb.responseTimes[kb.responseTimeMode])

                if deviation is not None and deviation > WARN_TIME_STDEV:
                    kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE

                    warnMsg = "considerable lagging has been detected "
                    warnMsg += "in connection response(s). Please use as high "
                    warnMsg += "value for option '--time-sec' as possible (e.g. "
                    warnMsg += "10 or more)"
                    logger.critical(warnMsg)

        if (conf.safeFreq or 0) > 0:
            kb.queryCounter += 1
            if kb.queryCounter % conf.safeFreq == 0:
                if conf.safeUrl:
                    Connect.getPage(url=conf.safeUrl, post=conf.safePost, cookie=cookie, direct=True, silent=True, ua=ua, referer=referer, host=host)
                elif kb.safeReq:
                    Connect.getPage(url=kb.safeReq.url, post=kb.safeReq.post, method=kb.safeReq.method, auxHeaders=kb.safeReq.headers)

        start = time.time()

        if kb.nullConnection and not content and not response and not timeBasedCompare:
            noteResponseTime = False

            try:
                pushValue(kb.pageCompress)
                kb.pageCompress = False

                if kb.nullConnection == NULLCONNECTION.HEAD:
                    method = HTTPMETHOD.HEAD
                elif kb.nullConnection == NULLCONNECTION.RANGE:
                    auxHeaders[HTTP_HEADER.RANGE] = "bytes=-1"

                _, headers, code = Connect.getPage(url=uri, get=get, post=post, method=method, cookie=cookie, ua=ua, referer=referer, host=host, silent=silent, auxHeaders=auxHeaders, raise404=raise404, skipRead=(kb.nullConnection == NULLCONNECTION.SKIP_READ))

                if headers:
                    try:
                        if kb.nullConnection in (NULLCONNECTION.HEAD, NULLCONNECTION.SKIP_READ) and headers.get(HTTP_HEADER.CONTENT_LENGTH):
                            pageLength = int(headers[HTTP_HEADER.CONTENT_LENGTH].split(',')[0])
                        elif kb.nullConnection == NULLCONNECTION.RANGE and headers.get(HTTP_HEADER.CONTENT_RANGE):
                            pageLength = int(headers[HTTP_HEADER.CONTENT_RANGE][headers[HTTP_HEADER.CONTENT_RANGE].find('/') + 1:])
                    except ValueError:
                        pass
            finally:
                kb.pageCompress = popValue()

        if pageLength is None:
            try:
                page, headers, code = Connect.getPage(url=uri, get=get, post=post, method=method, cookie=cookie, ua=ua, referer=referer, host=host, silent=silent, auxHeaders=auxHeaders, response=response, raise404=raise404, ignoreTimeout=timeBasedCompare)
            except MemoryError:
                page, headers, code = None, None, None
                warnMsg = "site returned insanely large response"
                if kb.testMode:
                    warnMsg += " in testing phase. This is a common "
                    warnMsg += "behavior in custom WAF/IPS solutions"
                singleTimeWarnMessage(warnMsg)

        if not ignoreSecondOrder:
            if conf.secondUrl:
                page, headers, code = Connect.getPage(url=conf.secondUrl, cookie=cookie, ua=ua, silent=silent, auxHeaders=auxHeaders, response=response, raise404=False, ignoreTimeout=timeBasedCompare, refreshing=True)
            elif kb.secondReq and IPS_WAF_CHECK_PAYLOAD not in _urllib.parse.unquote(value or ""):
                def _(value):
                    if kb.customInjectionMark in (value or ""):
                        if payload is None:
                            value = value.replace(kb.customInjectionMark, "")
                        else:
                            value = re.sub(r"\w*%s" % re.escape(kb.customInjectionMark), payload, value)
                    return value
                page, headers, code = Connect.getPage(url=_(kb.secondReq[0]), post=_(kb.secondReq[2]), method=kb.secondReq[1], cookie=kb.secondReq[3], silent=silent, auxHeaders=dict(auxHeaders, **dict(kb.secondReq[4])), response=response, raise404=False, ignoreTimeout=timeBasedCompare, refreshing=True)

        threadData.lastQueryDuration = calculateDeltaSeconds(start)

        kb.originalCode = code if kb.originalCode is None else kb.originalCode
        kb.originalPage = page if kb.originalPage is None else kb.originalPage

        if kb.testMode:
            kb.testQueryCount += 1

        if timeBasedCompare:
            return wasLastResponseDelayed()
        elif noteResponseTime:
            kb.responseTimes.setdefault(kb.responseTimeMode, [])
            kb.responseTimes[kb.responseTimeMode].append(threadData.lastQueryDuration)
            if len(kb.responseTimes[kb.responseTimeMode]) > MAX_TIME_RESPONSES:
                kb.responseTimes[kb.responseTimeMode] = kb.responseTimes[kb.responseTimeMode][-MAX_TIME_RESPONSES // 2:]

        if not response and removeReflection:
            page = removeReflectiveValues(page, payload)

        kb.maxConnectionsFlag = re.search(MAX_CONNECTIONS_REGEX, page or "", re.I) is not None

        message = extractRegexResult(PERMISSION_DENIED_REGEX, page or "", re.I)
        if message:
            kb.permissionFlag = True
            singleTimeWarnMessage("potential permission problems detected ('%s')" % message)

        headers = patchHeaders(headers)

        if content or response:
            return page, headers, code

        if getRatioValue:
            return comparison(page, headers, code, getRatioValue=False, pageLength=pageLength), comparison(page, headers, code, getRatioValue=True, pageLength=pageLength)
        else:
            return comparison(page, headers, code, getRatioValue, pageLength)

def setHTTPHandlers():  # Cross-referenced function
    raise NotImplementedError
