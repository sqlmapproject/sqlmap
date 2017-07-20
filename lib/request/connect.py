#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import binascii
import compiler
import httplib
import json
import keyword
import logging
import re
import socket
import string
import struct
import time
import traceback
import urllib2
import urlparse

try:
    import websocket
    from websocket import WebSocketException
except ImportError:
    class WebSocketException(Exception):
        pass

from extra.safe2bin.safe2bin import safecharencode
from lib.core.agent import agent
from lib.core.common import asciifyUrl
from lib.core.common import calculateDeltaSeconds
from lib.core.common import checkSameHost
from lib.core.common import clearConsoleLine
from lib.core.common import dataToStdout
from lib.core.common import evaluateCode
from lib.core.common import extractRegexResult
from lib.core.common import findMultipartPostBoundary
from lib.core.common import getCurrentThreadData
from lib.core.common import getHeader
from lib.core.common import getHostHeader
from lib.core.common import getRequestHeader
from lib.core.common import getSafeExString
from lib.core.common import getUnicode
from lib.core.common import logHTTPTraffic
from lib.core.common import pushValue
from lib.core.common import popValue
from lib.core.common import randomizeParameterValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import removeReflectiveValues
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import stdev
from lib.core.common import wasLastResponseDelayed
from lib.core.common import unicodeencode
from lib.core.common import urldecode
from lib.core.common import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.dicts import POST_HINT_CONTENT_TYPES
from lib.core.enums import ADJUST_TIME_DELAY
from lib.core.enums import AUTH_TYPE
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NULLCONNECTION
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.enums import POST_HINT
from lib.core.enums import REDIRECTION
from lib.core.enums import WEB_API
from lib.core.exception import SqlmapCompressionException
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapSyntaxException
from lib.core.exception import SqlmapTokenException
from lib.core.exception import SqlmapValueException
from lib.core.settings import ASTERISK_MARKER
from lib.core.settings import BOUNDARY_BACKSLASH_MARKER
from lib.core.settings import DEFAULT_CONTENT_TYPE
from lib.core.settings import DEFAULT_COOKIE_DELIMITER
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import EVALCODE_KEYWORD_SUFFIX
from lib.core.settings import HTTP_ACCEPT_HEADER_VALUE
from lib.core.settings import HTTP_ACCEPT_ENCODING_HEADER_VALUE
from lib.core.settings import MAX_CONNECTION_CHUNK_SIZE
from lib.core.settings import MAX_CONNECTIONS_REGEX
from lib.core.settings import MAX_CONNECTION_TOTAL_SIZE
from lib.core.settings import MAX_CONSECUTIVE_CONNECTION_ERRORS
from lib.core.settings import MAX_MURPHY_SLEEP_TIME
from lib.core.settings import META_REFRESH_REGEX
from lib.core.settings import MIN_TIME_RESPONSES
from lib.core.settings import IS_WIN
from lib.core.settings import LARGE_CHUNK_TRIM_MARKER
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
from lib.request.basic import decodePage
from lib.request.basic import forgeHeaders
from lib.request.basic import processResponse
from lib.request.direct import direct
from lib.request.comparison import comparison
from lib.request.methodrequest import MethodRequest
from thirdparty.odict.odict import OrderedDict
from thirdparty.socks.socks import ProxyError


class Connect(object):
    """
    This class defines methods used to perform HTTP requests
    """

    @staticmethod
    def _getPageProxy(**kwargs):
        try:
            return Connect.getPage(**kwargs)
        except RuntimeError:
            return None, None, None

    @staticmethod
    def _retryProxy(**kwargs):
        threadData = getCurrentThreadData()
        threadData.retriesCount += 1

        if conf.proxyList and threadData.retriesCount >= conf.retries:
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
                    warnMsg += "(e.g. 'https://www.torproject.org/download/download.html.en')"
                else:
                    warnMsg += "(e.g. 'https://help.ubuntu.com/community/Tor')"
            else:
                warnMsg = "if the problem persists please check that the provided "
                warnMsg += "target URL is valid. In case that it is, you can try to rerun "
                warnMsg += "with the switch '--random-agent' turned on "
                warnMsg += "and/or proxy switches ('--ignore-proxy', '--proxy',...)"
            singleTimeWarnMessage(warnMsg)

        elif conf.threads > 1:
            warnMsg = "if the problem persists please try to lower "
            warnMsg += "the number of used threads (option '--threads')"
            singleTimeWarnMessage(warnMsg)

        kwargs['retrying'] = True
        return Connect._getPageProxy(**kwargs)

    @staticmethod
    def _connReadProxy(conn):
        retVal = ""

        if not kb.dnsMode and conn:
            headers = conn.info()
            if headers and hasattr(headers, "getheader") and (headers.getheader(HTTP_HEADER.CONTENT_ENCODING, "").lower() in ("gzip", "deflate")\
              or "text" not in headers.getheader(HTTP_HEADER.CONTENT_TYPE, "").lower()):
                retVal = conn.read(MAX_CONNECTION_TOTAL_SIZE)
                if len(retVal) == MAX_CONNECTION_TOTAL_SIZE:
                    warnMsg = "large compressed response detected. Disabling compression"
                    singleTimeWarnMessage(warnMsg)
                    kb.pageCompress = False
            else:
                while True:
                    if not conn:
                        break
                    else:
                        _ = conn.read(MAX_CONNECTION_CHUNK_SIZE)

                    if len(_) == MAX_CONNECTION_CHUNK_SIZE:
                        warnMsg = "large response detected. This could take a while"
                        singleTimeWarnMessage(warnMsg)
                        _ = re.sub(r"(?si)%s.+?%s" % (kb.chars.stop, kb.chars.start), "%s%s%s" % (kb.chars.stop, LARGE_CHUNK_TRIM_MARKER, kb.chars.start), _)
                        retVal += _
                    else:
                        retVal += _
                        break

                    if len(retVal) > MAX_CONNECTION_TOTAL_SIZE:
                        warnMsg = "too large response detected. Automatically trimming it"
                        singleTimeWarnMessage(warnMsg)
                        break

        return retVal

    @staticmethod
    def getPage(**kwargs):
        """
        This method connects to the target URL or proxy and returns
        the target URL page content
        """

        start = time.time()

        if isinstance(conf.delay, (int, float)) and conf.delay > 0:
            time.sleep(conf.delay)

        if conf.offline:
            return None, None, None
        elif conf.dummy or conf.murphyRate and randomInt() % conf.murphyRate == 0:
            if conf.murphyRate:
                time.sleep(randomInt() % (MAX_MURPHY_SLEEP_TIME + 1))
            return getUnicode(randomStr(int(randomInt()), alphabet=[chr(_) for _ in xrange(256)]), {}, int(randomInt())), None, None if not conf.murphyRate else randomInt(3)

        threadData = getCurrentThreadData()
        with kb.locks.request:
            kb.requestCounter += 1
            threadData.lastRequestUID = kb.requestCounter

        url = kwargs.get("url",                     None) or conf.url
        get = kwargs.get("get",                     None)
        post = kwargs.get("post",                   None)
        method = kwargs.get("method",               None)
        cookie = kwargs.get("cookie",               None)
        ua = kwargs.get("ua",                       None) or conf.agent
        referer = kwargs.get("referer",             None) or conf.referer
        host = kwargs.get("host",                   None) or conf.host
        direct_ = kwargs.get("direct",              False)
        multipart = kwargs.get("multipart",         None)
        silent = kwargs.get("silent",               False)
        raise404 = kwargs.get("raise404",           True)
        timeout = kwargs.get("timeout",             None) or conf.timeout
        auxHeaders = kwargs.get("auxHeaders",       None)
        response = kwargs.get("response",           False)
        ignoreTimeout = kwargs.get("ignoreTimeout", False) or kb.ignoreTimeout or conf.ignoreTimeouts
        refreshing = kwargs.get("refreshing",       False)
        retrying = kwargs.get("retrying",           False)
        crawling = kwargs.get("crawling",           False)
        checking = kwargs.get("checking",           False)
        skipRead = kwargs.get("skipRead",           False)

        if multipart:
            post = multipart

        websocket_ = url.lower().startswith("ws")

        if not urlparse.urlsplit(url).netloc:
            url = urlparse.urljoin(conf.url, url)

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

        _ = urlparse.urlsplit(url)
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
                if conf.forceSSL and urlparse.urlparse(url).scheme != "https":
                    url = re.sub("(?i)\Ahttp:", "https:", url)
                    url = re.sub("(?i):80/", ":443/", url)

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

            requestMsg += " %s" % httplib.HTTPConnection._http_vsn_str

            # Prepare HTTP headers
            headers = forgeHeaders({HTTP_HEADER.COOKIE: cookie, HTTP_HEADER.USER_AGENT: ua, HTTP_HEADER.REFERER: referer, HTTP_HEADER.HOST: host})

            if HTTP_HEADER.COOKIE in headers:
                cookie = headers[HTTP_HEADER.COOKIE]

            if kb.authHeader:
                headers[HTTP_HEADER.AUTHORIZATION] = kb.authHeader

            if kb.proxyAuthHeader:
                headers[HTTP_HEADER.PROXY_AUTHORIZATION] = kb.proxyAuthHeader

            if not getHeader(headers, HTTP_HEADER.ACCEPT):
                headers[HTTP_HEADER.ACCEPT] = HTTP_ACCEPT_HEADER_VALUE

            if not getHeader(headers, HTTP_HEADER.HOST) or not target:
                headers[HTTP_HEADER.HOST] = getHostHeader(url)

            if not getHeader(headers, HTTP_HEADER.ACCEPT_ENCODING):
                headers[HTTP_HEADER.ACCEPT_ENCODING] = HTTP_ACCEPT_ENCODING_HEADER_VALUE if kb.pageCompress else "identity"

            if post is not None and not multipart and not getHeader(headers, HTTP_HEADER.CONTENT_TYPE):
                headers[HTTP_HEADER.CONTENT_TYPE] = POST_HINT_CONTENT_TYPES.get(kb.postHint, DEFAULT_CONTENT_TYPE)

            if headers.get(HTTP_HEADER.CONTENT_TYPE) == POST_HINT_CONTENT_TYPES[POST_HINT.MULTIPART]:
                warnMsg = "missing 'boundary parameter' in '%s' header. " % HTTP_HEADER.CONTENT_TYPE
                warnMsg += "Will try to reconstruct"
                singleTimeWarnMessage(warnMsg)

                boundary = findMultipartPostBoundary(conf.data)
                if boundary:
                    headers[HTTP_HEADER.CONTENT_TYPE] = "%s; boundary=%s" % (headers[HTTP_HEADER.CONTENT_TYPE], boundary)

            if conf.keepAlive:
                headers[HTTP_HEADER.CONNECTION] = "keep-alive"

            # Reset header values to original in case of provided request file
            if target and conf.requestFile:
                headers = forgeHeaders({HTTP_HEADER.COOKIE: cookie})

            if auxHeaders:
                for key, value in auxHeaders.items():
                    for _ in headers.keys():
                        if _.upper() == key.upper():
                            del headers[_]
                    headers[key] = value

            for key, value in headers.items():
                del headers[key]
                value = unicodeencode(value, kb.pageEncoding)
                for char in (r"\r", r"\n"):
                    value = re.sub(r"(%s)([^ \t])" % char, r"\g<1>\t\g<2>", value)
                headers[unicodeencode(key, kb.pageEncoding)] = value.strip("\r\n")

            url = unicodeencode(url)
            post = unicodeencode(post)

            if websocket_:
                ws = websocket.WebSocket()
                ws.settimeout(timeout)
                ws.connect(url, header=("%s: %s" % _ for _ in headers.items() if _[0] not in ("Host",)), cookie=cookie)  # WebSocket will add Host field of headers automatically
                ws.send(urldecode(post or ""))
                page = ws.recv()
                ws.close()
                code = ws.status
                status = httplib.responses[code]
                class _(dict):
                    pass
                responseHeaders = _(ws.getheaders())
                responseHeaders.headers = ["%s: %s\r\n" % (_[0].capitalize(), _[1]) for _ in responseHeaders.items()]

                requestHeaders += "\r\n".join(["%s: %s" % (getUnicode(key.capitalize() if isinstance(key, basestring) else key), getUnicode(value)) for (key, value) in responseHeaders.items()])
                requestMsg += "\r\n%s" % requestHeaders

                if post is not None:
                    requestMsg += "\r\n\r\n%s" % getUnicode(post)

                requestMsg += "\r\n"

                threadData.lastRequestMsg = requestMsg

                logger.log(CUSTOM_LOGGING.TRAFFIC_OUT, requestMsg)
            else:
                if method and method not in (HTTPMETHOD.GET, HTTPMETHOD.POST):
                    method = unicodeencode(method)
                    req = MethodRequest(url, post, headers)
                    req.set_method(method)
                else:
                    req = urllib2.Request(url, post, headers)

                requestHeaders += "\r\n".join(["%s: %s" % (getUnicode(key.capitalize() if isinstance(key, basestring) else key), getUnicode(value)) for (key, value) in req.header_items()])

                if not getRequestHeader(req, HTTP_HEADER.COOKIE) and conf.cj:
                    conf.cj._policy._now = conf.cj._now = int(time.time())
                    cookies = conf.cj._cookies_for_request(req)
                    requestHeaders += "\r\n%s" % ("Cookie: %s" % ";".join("%s=%s" % (getUnicode(cookie.name), getUnicode(cookie.value)) for cookie in cookies))

                if post is not None:
                    if not getRequestHeader(req, HTTP_HEADER.CONTENT_LENGTH):
                        requestHeaders += "\r\n%s: %d" % (string.capwords(HTTP_HEADER.CONTENT_LENGTH), len(post))

                if not getRequestHeader(req, HTTP_HEADER.CONNECTION):
                    requestHeaders += "\r\n%s: %s" % (HTTP_HEADER.CONNECTION, "close" if not conf.keepAlive else "keep-alive")

                requestMsg += "\r\n%s" % requestHeaders

                if post is not None:
                    requestMsg += "\r\n\r\n%s" % getUnicode(post)

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

                conn = urllib2.urlopen(req)

                if not kb.authHeader and getRequestHeader(req, HTTP_HEADER.AUTHORIZATION) and (conf.authType or "").lower() == AUTH_TYPE.BASIC.lower():
                    kb.authHeader = getRequestHeader(req, HTTP_HEADER.AUTHORIZATION)

                if not kb.proxyAuthHeader and getRequestHeader(req, HTTP_HEADER.PROXY_AUTHORIZATION):
                    kb.proxyAuthHeader = getRequestHeader(req, HTTP_HEADER.PROXY_AUTHORIZATION)

                # Return response object
                if response:
                    return conn, None, None

                # Get HTTP response
                if hasattr(conn, "redurl"):
                    page = (threadData.lastRedirectMsg[1] if kb.redirectChoice == REDIRECTION.NO\
                    else Connect._connReadProxy(conn)) if not skipRead else None
                    skipLogTraffic = kb.redirectChoice == REDIRECTION.NO
                    code = conn.redcode
                else:
                    page = Connect._connReadProxy(conn) if not skipRead else None

                if conn:
                    code = conn.code
                    responseHeaders = conn.info()
                    responseHeaders[URI_HTTP_HEADER] = conn.geturl()
                else:
                    code = None
                    responseHeaders = {}

                page = decodePage(page, responseHeaders.get(HTTP_HEADER.CONTENT_ENCODING), responseHeaders.get(HTTP_HEADER.CONTENT_TYPE))
                status = getUnicode(conn.msg) if conn else None

            kb.connErrorCounter = 0

            if not refreshing:
                refresh = responseHeaders.get(HTTP_HEADER.REFRESH, "").split("url=")[-1].strip()

                if extractRegexResult(META_REFRESH_REGEX, page):
                    refresh = extractRegexResult(META_REFRESH_REGEX, page)

                    debugMsg = "got HTML meta refresh header"
                    logger.debug(debugMsg)

                if refresh:
                    if kb.alwaysRefresh is None:
                        msg = "sqlmap got a refresh request "
                        msg += "(redirect like response common to login pages). "
                        msg += "Do you want to apply the refresh "
                        msg += "from now on (or stay on the original page)? [Y/n]"

                        kb.alwaysRefresh = readInput(msg, default='Y', boolean=True)

                    if kb.alwaysRefresh:
                        if re.search(r"\Ahttps?://", refresh, re.I):
                            url = refresh
                        else:
                            url = urlparse.urljoin(url, refresh)

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
                except Exception, ex:
                    warnMsg = "problem occurred during connection closing ('%s')" % getSafeExString(ex)
                    logger.warn(warnMsg)

        except urllib2.HTTPError, ex:
            page = None
            responseHeaders = None

            if checking:
                return None, None, None

            try:
                page = ex.read() if not skipRead else None
                responseHeaders = ex.info()
                responseHeaders[URI_HTTP_HEADER] = ex.geturl()
                page = decodePage(page, responseHeaders.get(HTTP_HEADER.CONTENT_ENCODING), responseHeaders.get(HTTP_HEADER.CONTENT_TYPE))
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
                page = page if isinstance(page, unicode) else getUnicode(page)

            code = ex.code
            status = getUnicode(ex.msg)

            kb.originalCode = kb.originalCode or code
            threadData.lastHTTPError = (threadData.lastRequestUID, code, status)
            kb.httpErrorCodes[code] = kb.httpErrorCodes.get(code, 0) + 1

            responseMsg += "[#%d] (%d %s):\r\n" % (threadData.lastRequestUID, code, status)

            if responseHeaders:
                logHeaders = "\r\n".join(["%s: %s" % (getUnicode(key.capitalize() if isinstance(key, basestring) else key), getUnicode(value)) for (key, value) in responseHeaders.items()])

            logHTTPTraffic(requestMsg, "%s%s\r\n\r\n%s" % (responseMsg, logHeaders, (page or "")[:MAX_CONNECTION_CHUNK_SIZE]), start, time.time())

            skipLogTraffic = True

            if conf.verbose <= 5:
                responseMsg += getUnicode(logHeaders)
            elif conf.verbose > 5:
                responseMsg += "%s\r\n\r\n%s" % (logHeaders, (page or "")[:MAX_CONNECTION_CHUNK_SIZE])

            if not multipart:
                logger.log(CUSTOM_LOGGING.TRAFFIC_IN, responseMsg)

            if ex.code == httplib.UNAUTHORIZED and not conf.ignore401:
                errMsg = "not authorized, try to provide right HTTP "
                errMsg += "authentication type and valid credentials (%d)" % code
                raise SqlmapConnectionException(errMsg)
            elif ex.code == httplib.NOT_FOUND:
                if raise404:
                    errMsg = "page not found (%d)" % code
                    raise SqlmapConnectionException(errMsg)
                else:
                    debugMsg = "page not found (%d)" % code
                    singleTimeLogMessage(debugMsg, logging.DEBUG)
            elif ex.code == httplib.GATEWAY_TIMEOUT:
                if ignoreTimeout:
                    return None if not conf.ignoreTimeouts else "", None, None
                else:
                    warnMsg = "unable to connect to the target URL (%d - %s)" % (ex.code, httplib.responses[ex.code])
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
                debugMsg = "got HTTP error code: %d (%s)" % (code, status)
                logger.debug(debugMsg)

        except (urllib2.URLError, socket.error, socket.timeout, httplib.HTTPException, struct.error, binascii.Error, ProxyError, SqlmapCompressionException, WebSocketException, TypeError, ValueError):
            tbMsg = traceback.format_exc()

            if checking:
                return None, None, None
            elif "no host given" in tbMsg:
                warnMsg = "invalid URL address used (%s)" % repr(url)
                raise SqlmapSyntaxException(warnMsg)
            elif "forcibly closed" in tbMsg or "Connection is already closed" in tbMsg:
                warnMsg = "connection was forcibly closed by the target URL"
            elif "timed out" in tbMsg:
                if not conf.disablePrecon:
                    singleTimeWarnMessage("turning off pre-connect mechanism because of connection time out(s)")
                    conf.disablePrecon = True

                    if kb.testMode and kb.testType not in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED):
                        kb.responseTimes.clear()

                if kb.testMode and kb.testType not in (None, PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED):
                    singleTimeWarnMessage("there is a possibility that the target (or WAF/IPS/IDS) is dropping 'suspicious' requests")
                    kb.droppingRequests = True
                warnMsg = "connection timed out to the target URL"
            elif "Connection reset" in tbMsg:
                if not conf.disablePrecon:
                    singleTimeWarnMessage("turning off pre-connect mechanism because of connection reset(s)")
                    conf.disablePrecon = True

                if kb.testMode:
                    singleTimeWarnMessage("there is a possibility that the target (or WAF/IPS/IDS) is resetting 'suspicious' requests")
                    kb.droppingRequests = True
                warnMsg = "connection reset to the target URL"
            elif "URLError" in tbMsg or "error" in tbMsg:
                warnMsg = "unable to connect to the target URL"
                match = re.search(r"Errno \d+\] ([^>]+)", tbMsg)
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
                status = re.search("Handshake status ([\d]{3})", tbMsg)
                errMsg = "websocket handshake status %s" % status.group(1) if status else "unknown"
                raise SqlmapConnectionException(errMsg)
            else:
                warnMsg = "unable to connect to the target URL"

            if "BadStatusLine" not in tbMsg and any((conf.proxy, conf.tor)):
                warnMsg += " or proxy"

            if silent:
                return None, None, None

            with kb.locks.connError:
                kb.connErrorCounter += 1

                if kb.connErrorCounter >= MAX_CONSECUTIVE_CONNECTION_ERRORS and kb.connErrorChoice is None:
                    message = "there seems to be a continuous problem with connection to the target. "
                    message += "Are you sure that you want to continue "
                    message += "with further target testing? [y/N] "

                    kb.connErrorChoice = readInput(message, default='N', boolean=True)

                if kb.connErrorChoice is False:
                    raise SqlmapConnectionException(warnMsg)

            if "forcibly closed" in tbMsg:
                logger.critical(warnMsg)
                return None, None, None
            elif ignoreTimeout and any(_ in tbMsg for _ in ("timed out", "IncompleteRead")):
                return None if not conf.ignoreTimeouts else "", None, None
            elif threadData.retriesCount < conf.retries and not kb.threadException:
                warnMsg += ". sqlmap is going to retry the request"
                if not retrying:
                    warnMsg += "(s)"
                    logger.critical(warnMsg)
                else:
                    logger.debug(warnMsg)
                return Connect._retryProxy(**kwargs)
            elif kb.testMode:
                logger.critical(warnMsg)
                return None, None, None
            else:
                raise SqlmapConnectionException(warnMsg)

        finally:
            if isinstance(page, basestring) and not isinstance(page, unicode):
                if HTTP_HEADER.CONTENT_TYPE in (responseHeaders or {}) and not re.search(TEXT_CONTENT_TYPE_REGEX, responseHeaders[HTTP_HEADER.CONTENT_TYPE]):
                    page = unicode(page, errors="ignore")
                else:
                    page = getUnicode(page)
            socket.setdefaulttimeout(conf.timeout)

        processResponse(page, responseHeaders, status)

        if conn and getattr(conn, "redurl", None):
            _ = urlparse.urlsplit(conn.redurl)
            _ = ("%s%s" % (_.path or "/", ("?%s" % _.query) if _.query else ""))
            requestMsg = re.sub("(\n[A-Z]+ ).+?( HTTP/\d)", "\g<1>%s\g<2>" % getUnicode(_).replace("\\", "\\\\"), requestMsg, 1)

            if kb.resendPostOnRedirect is False:
                requestMsg = re.sub("(\[#\d+\]:\n)POST ", "\g<1>GET ", requestMsg)
                requestMsg = re.sub("(?i)Content-length: \d+\n", "", requestMsg)
                requestMsg = re.sub("(?s)\n\n.+", "\n", requestMsg)

            responseMsg += "[#%d] (%d %s):\r\n" % (threadData.lastRequestUID, conn.code, status)
        else:
            responseMsg += "[#%d] (%d %s):\r\n" % (threadData.lastRequestUID, code, status)

        if responseHeaders:
            logHeaders = "\r\n".join(["%s: %s" % (getUnicode(key.capitalize() if isinstance(key, basestring) else key), getUnicode(value)) for (key, value) in responseHeaders.items()])

        if not skipLogTraffic:
            logHTTPTraffic(requestMsg, "%s%s\r\n\r\n%s" % (responseMsg, logHeaders, (page or "")[:MAX_CONNECTION_CHUNK_SIZE]), start, time.time())

        if conf.verbose <= 5:
            responseMsg += getUnicode(logHeaders)
        elif conf.verbose > 5:
            responseMsg += "%s\r\n\r\n%s" % (logHeaders, (page or "")[:MAX_CONNECTION_CHUNK_SIZE])

        if not multipart:
            logger.log(CUSTOM_LOGGING.TRAFFIC_IN, responseMsg)

        return page, responseHeaders, code

    @staticmethod
    def queryPage(value=None, place=None, content=False, getRatioValue=False, silent=False, method=None, timeBasedCompare=False, noteResponseTime=True, auxHeaders=None, response=False, raise404=None, removeReflection=True):
        """
        This method calls a function to get the target URL page content
        and returns its page MD5 hash or a boolean value in case of
        string match check ('--string' command line parameter)
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

        if not auxHeaders:
            auxHeaders = {}

        raise404 = place != PLACE.URI if raise404 is None else raise404
        method = method or conf.method

        value = agent.adjustLateValues(value)
        payload = agent.extractPayload(value)
        threadData = getCurrentThreadData()

        if conf.httpHeaders:
            headers = OrderedDict(conf.httpHeaders)
            contentType = max(headers[_] if _.upper() == HTTP_HEADER.CONTENT_TYPE.upper() else None for _ in headers.keys())

            if (kb.postHint or conf.skipUrlEncode) and kb.postUrlEncode:
                kb.postUrlEncode = False
                conf.httpHeaders = [_ for _ in conf.httpHeaders if _[1] != contentType]
                contentType = POST_HINT_CONTENT_TYPES.get(kb.postHint, PLAIN_TEXT_CONTENT_TYPE)
                conf.httpHeaders.append((HTTP_HEADER.CONTENT_TYPE, contentType))

        if payload:
            if kb.tamperFunctions:
                for function in kb.tamperFunctions:
                    try:
                        payload = function(payload=payload, headers=auxHeaders)
                    except Exception, ex:
                        errMsg = "error occurred while running tamper "
                        errMsg += "function '%s' ('%s')" % (function.func_name, getSafeExString(ex))
                        raise SqlmapGenericException(errMsg)

                    if not isinstance(payload, basestring):
                        errMsg = "tamper function '%s' returns " % function.func_name
                        errMsg += "invalid payload type ('%s')" % type(payload)
                        raise SqlmapValueException(errMsg)

                value = agent.replacePayload(value, payload)

            logger.log(CUSTOM_LOGGING.PAYLOAD, safecharencode(payload.replace('\\', BOUNDARY_BACKSLASH_MARKER)).replace(BOUNDARY_BACKSLASH_MARKER, '\\'))

            if place == PLACE.CUSTOM_POST and kb.postHint:
                if kb.postHint in (POST_HINT.SOAP, POST_HINT.XML):
                    # payloads in SOAP/XML should have chars > and < replaced
                    # with their HTML encoded counterparts
                    payload = payload.replace('>', "&gt;").replace('<', "&lt;")
                elif kb.postHint == POST_HINT.JSON:
                    if payload.startswith('"') and payload.endswith('"'):
                        payload = json.dumps(payload[1:-1])
                    else:
                        payload = json.dumps(payload)[1:-1]
                elif kb.postHint == POST_HINT.JSON_LIKE:
                    payload = payload.replace("'", REPLACEMENT_MARKER).replace('"', "'").replace(REPLACEMENT_MARKER, '"')
                    if payload.startswith('"') and payload.endswith('"'):
                        payload = json.dumps(payload[1:-1])
                    else:
                        payload = json.dumps(payload)[1:-1]
                    payload = payload.replace("'", REPLACEMENT_MARKER).replace('"', "'").replace(REPLACEMENT_MARKER, '"')
                value = agent.replacePayload(value, payload)
            else:
                # GET, POST, URI and Cookie payload needs to be thoroughly URL encoded
                if (place in (PLACE.GET, PLACE.URI, PLACE.COOKIE) or place == PLACE.CUSTOM_HEADER and value.split(',')[0] == HTTP_HEADER.COOKIE) and not conf.skipUrlEncode or place in (PLACE.POST, PLACE.CUSTOM_POST) and kb.postUrlEncode:
                    skip = False

                    if place == PLACE.COOKIE or place == PLACE.CUSTOM_HEADER and value.split(',')[0] == HTTP_HEADER.COOKIE:
                        if kb.cookieEncodeChoice is None:
                            msg = "do you want to URL encode cookie values (implementation specific)? %s" % ("[Y/n]" if not conf.url.endswith(".aspx") else "[y/N]")  # Reference: https://support.microsoft.com/en-us/kb/313282
                            choice = readInput(msg, default='Y' if not conf.url.endswith(".aspx") else 'N')
                            kb.cookieEncodeChoice = choice.upper().strip() == 'Y'
                        if not kb.cookieEncodeChoice:
                            skip = True

                    if not skip:
                        payload = urlencode(payload, '%', False, place != PLACE.URI)  # spaceplus is handled down below
                        value = agent.replacePayload(value, payload)

            if conf.hpp:
                if not any(conf.url.lower().endswith(_.lower()) for _ in (WEB_API.ASP, WEB_API.ASPX)):
                    warnMsg = "HTTP parameter pollution should work only against "
                    warnMsg += "ASP(.NET) targets"
                    singleTimeWarnMessage(warnMsg)
                if place in (PLACE.GET, PLACE.POST):
                    _ = re.escape(PAYLOAD_DELIMITER)
                    match = re.search("(?P<name>\w+)=%s(?P<value>.+?)%s" % (_, _), value)
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
                cookie = value.split(',', 1)[1]
            else:
                auxHeaders[value.split(',')[0]] = value.split(',', 1)[1]

        if conf.csrfToken:
            def _adjustParameter(paramString, parameter, newValue):
                retVal = paramString
                match = re.search("%s=[^&]*" % re.escape(parameter), paramString)
                if match:
                    retVal = re.sub(re.escape(match.group(0)), "%s=%s" % (parameter, newValue), paramString)
                else:
                    match = re.search("(%s[\"']:[\"'])([^\"']+)" % re.escape(parameter), paramString)
                    if match:
                        retVal = re.sub(re.escape(match.group(0)), "%s%s" % (match.group(1), newValue), paramString)
                return retVal

            page, headers, code = Connect.getPage(url=conf.csrfUrl or conf.url, data=conf.data if conf.csrfUrl == conf.url else None, method=conf.method if conf.csrfUrl == conf.url else None, cookie=conf.parameters.get(PLACE.COOKIE), direct=True, silent=True, ua=conf.parameters.get(PLACE.USER_AGENT), referer=conf.parameters.get(PLACE.REFERER), host=conf.parameters.get(PLACE.HOST))
            match = re.search(r"<input[^>]+name=[\"']?%s[\"']?\s[^>]*value=(\"([^\"]+)|'([^']+)|([^ >]+))" % re.escape(conf.csrfToken), page or "")
            token = (match.group(2) or match.group(3) or match.group(4)) if match else None

            if not token:
                match = re.search(r"%s[\"']:[\"']([^\"']+)" % re.escape(conf.csrfToken), page or "")
                token = match.group(1) if match else None

            if not token:
                if conf.csrfUrl != conf.url and code == httplib.OK:
                    if headers and "text/plain" in headers.get(HTTP_HEADER.CONTENT_TYPE, ""):
                        token = page

                if not token and conf.cj and any(_.name == conf.csrfToken for _ in conf.cj):
                    for _ in conf.cj:
                        if _.name == conf.csrfToken:
                            token = _.value
                            if not any(conf.csrfToken in _ for _ in (conf.paramDict.get(PLACE.GET, {}), conf.paramDict.get(PLACE.POST, {}))):
                                if post:
                                    post = "%s%s%s=%s" % (post, conf.paramDel or DEFAULT_GET_POST_DELIMITER, conf.csrfToken, token)
                                elif get:
                                    get = "%s%s%s=%s" % (get, conf.paramDel or DEFAULT_GET_POST_DELIMITER, conf.csrfToken, token)
                                else:
                                    get = "%s=%s" % (conf.csrfToken, token)
                            break

                if not token:
                    errMsg = "anti-CSRF token '%s' can't be found at '%s'" % (conf.csrfToken, conf.csrfUrl or conf.url)
                    if not conf.csrfUrl:
                        errMsg += ". You can try to rerun by providing "
                        errMsg += "a valid value for option '--csrf-url'"
                    raise SqlmapTokenException, errMsg

            if token:
                for place in (PLACE.GET, PLACE.POST):
                    if place in conf.parameters:
                        if place == PLACE.GET and get:
                            get = _adjustParameter(get, conf.csrfToken, token)
                        elif place == PLACE.POST and post:
                            post = _adjustParameter(post, conf.csrfToken, token)

                for i in xrange(len(conf.httpHeaders)):
                    if conf.httpHeaders[i][0].lower() == conf.csrfToken.lower():
                        conf.httpHeaders[i] = (conf.httpHeaders[i][0], token)

        if conf.rParam:
            def _randomizeParameter(paramString, randomParameter):
                retVal = paramString
                match = re.search(r"(\A|\b)%s=(?P<value>[^&;]+)" % re.escape(randomParameter), paramString)
                if match:
                    origValue = match.group("value")
                    retVal = re.sub(r"(\A|\b)%s=[^&;]+" % re.escape(randomParameter), "%s=%s" % (randomParameter, randomizeParameterValue(origValue)), paramString)
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
            variables = {"uri": uri, "lastPage": threadData.lastPage, "_locals": locals()}
            originals = {}
            keywords = keyword.kwlist

            if not get and PLACE.URI in conf.parameters:
                query = urlparse.urlsplit(uri).query or ""
            else:
                query = None

            for item in filter(None, (get, post if not kb.postHint else None, query)):
                for part in item.split(delimiter):
                    if '=' in part:
                        name, value = part.split('=', 1)
                        name = re.sub(r"[^\w]", "", name.strip())
                        if name in keywords:
                            name = "%s%s" % (name, EVALCODE_KEYWORD_SUFFIX)
                        value = urldecode(value, convall=True, plusspace=(item==post and kb.postSpaceToPlus))
                        variables[name] = value

            if cookie:
                for part in cookie.split(conf.cookieDel or DEFAULT_COOKIE_DELIMITER):
                    if '=' in part:
                        name, value = part.split('=', 1)
                        name = re.sub(r"[^\w]", "", name.strip())
                        if name in keywords:
                            name = "%s%s" % (name, EVALCODE_KEYWORD_SUFFIX)
                        value = urldecode(value, convall=True)
                        variables[name] = value

            while True:
                try:
                    compiler.parse(unicodeencode(conf.evalCode.replace(';', '\n')))
                except SyntaxError, ex:
                    if ex.text:
                        original = replacement = ex.text.strip()
                        for _ in re.findall(r"[A-Za-z_]+", original)[::-1]:
                            if _ in keywords:
                                replacement = replacement.replace(_, "%s%s" % (_, EVALCODE_KEYWORD_SUFFIX))
                                break
                        if original == replacement:
                            conf.evalCode = conf.evalCode.replace(EVALCODE_KEYWORD_SUFFIX, "")
                            break
                        else:
                            conf.evalCode = conf.evalCode.replace(getUnicode(ex.text.strip(), UNICODE_ENCODING), replacement)
                    else:
                        break
                else:
                    break

            originals.update(variables)
            evaluateCode(conf.evalCode, variables)

            for variable in variables.keys():
                if variable.endswith(EVALCODE_KEYWORD_SUFFIX):
                    value = variables[variable]
                    del variables[variable]
                    variables[variable.replace(EVALCODE_KEYWORD_SUFFIX, "")] = value

            uri = variables["uri"]

            for name, value in variables.items():
                if name != "__builtins__" and originals.get(name, "") != value:
                    if isinstance(value, (basestring, int)):
                        found = False
                        value = getUnicode(value, UNICODE_ENCODING)

                        if kb.postHint and re.search(r"\b%s\b" % re.escape(name), post or ""):
                            if kb.postHint in (POST_HINT.XML, POST_HINT.SOAP):
                                if re.search(r"<%s\b" % re.escape(name), post):
                                    found = True
                                    post = re.sub(r"(?s)(<%s\b[^>]*>)(.*?)(</%s)" % (re.escape(name), re.escape(name)), "\g<1>%s\g<3>" % value, post)
                                elif re.search(r"\b%s>" % re.escape(name), post):
                                    found = True
                                    post = re.sub(r"(?s)(\b%s>)(.*?)(</[^<]*\b%s>)" % (re.escape(name), re.escape(name)), "\g<1>%s\g<3>" % value, post)

                            regex = r"\b(%s)\b([^\w]+)(\w+)" % re.escape(name)
                            if not found and re.search(regex, (post or "")):
                                found = True
                                post = re.sub(regex, "\g<1>\g<2>%s" % value, post)

                        regex = r"((\A|%s)%s=).+?(%s|\Z)" % (re.escape(delimiter), re.escape(name), re.escape(delimiter))
                        if not found and re.search(regex, (post or "")):
                            found = True
                            post = re.sub(regex, "\g<1>%s\g<3>" % value, post)

                        if re.search(regex, (get or "")):
                            found = True
                            get = re.sub(regex, "\g<1>%s\g<3>" % value, get)

                        if re.search(regex, (query or "")):
                            found = True
                            uri = re.sub(regex.replace(r"\A", r"\?"), "\g<1>%s\g<3>" % value, uri)

                        regex = r"((\A|%s)%s=).+?(%s|\Z)" % (re.escape(conf.cookieDel or DEFAULT_COOKIE_DELIMITER), name, re.escape(conf.cookieDel or DEFAULT_COOKIE_DELIMITER))
                        if re.search(regex, (cookie or "")):
                            found = True
                            cookie = re.sub(regex, "\g<1>%s\g<3>" % value, cookie)

                        if not found:
                            if post is not None:
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
            elif kb.postUrlEncode:
                post = urlencode(post, spaceplus=kb.postSpaceToPlus)

        if timeBasedCompare and not conf.disableStats:
            if len(kb.responseTimes.get(kb.responseTimeMode, [])) < MIN_TIME_RESPONSES:
                clearConsoleLine()

                kb.responseTimes.setdefault(kb.responseTimeMode, [])

                if conf.tor:
                    warnMsg = "it's highly recommended to avoid usage of switch '--tor' for "
                    warnMsg += "time-based injections because of its high latency time"
                    singleTimeWarnMessage(warnMsg)

                warnMsg = "[%s] [WARNING] %stime-based comparison requires " % (time.strftime("%X"), "(case) " if kb.responseTimeMode else "")
                warnMsg += "larger statistical model, please wait"
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

                if deviation > WARN_TIME_STDEV:
                    kb.adjustTimeDelay = ADJUST_TIME_DELAY.DISABLE

                    warnMsg = "considerable lagging has been detected "
                    warnMsg += "in connection response(s). Please use as high "
                    warnMsg += "value for option '--time-sec' as possible (e.g. "
                    warnMsg += "10 or more)"
                    logger.critical(warnMsg)

        if conf.safeFreq > 0:
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
                    if kb.nullConnection in (NULLCONNECTION.HEAD, NULLCONNECTION.SKIP_READ) and headers.get(HTTP_HEADER.CONTENT_LENGTH):
                        pageLength = int(headers[HTTP_HEADER.CONTENT_LENGTH])
                    elif kb.nullConnection == NULLCONNECTION.RANGE and headers.get(HTTP_HEADER.CONTENT_RANGE):
                        pageLength = int(headers[HTTP_HEADER.CONTENT_RANGE][headers[HTTP_HEADER.CONTENT_RANGE].find('/') + 1:])
            finally:
                kb.pageCompress = popValue()

        if not pageLength:
            try:
                page, headers, code = Connect.getPage(url=uri, get=get, post=post, method=method, cookie=cookie, ua=ua, referer=referer, host=host, silent=silent, auxHeaders=auxHeaders, response=response, raise404=raise404, ignoreTimeout=timeBasedCompare)
            except MemoryError:
                page, headers, code = None, None, None
                warnMsg = "site returned insanely large response"
                if kb.testMode:
                    warnMsg += " in testing phase. This is a common "
                    warnMsg += "behavior in custom WAF/IPS/IDS solutions"
                singleTimeWarnMessage(warnMsg)

        if conf.secondOrder:
            page, headers, code = Connect.getPage(url=conf.secondOrder, cookie=cookie, ua=ua, silent=silent, auxHeaders=auxHeaders, response=response, raise404=False, ignoreTimeout=timeBasedCompare, refreshing=True)

        threadData.lastQueryDuration = calculateDeltaSeconds(start)
        threadData.lastPage = page
        threadData.lastCode = code

        kb.originalCode = kb.originalCode or code

        if kb.testMode:
            kb.testQueryCount += 1

        if timeBasedCompare:
            return wasLastResponseDelayed()
        elif noteResponseTime:
            kb.responseTimes.setdefault(kb.responseTimeMode, [])
            kb.responseTimes[kb.responseTimeMode].append(threadData.lastQueryDuration)

        if not response and removeReflection:
            page = removeReflectiveValues(page, payload)

        kb.maxConnectionsFlag = re.search(MAX_CONNECTIONS_REGEX, page or "", re.I) is not None
        kb.permissionFlag = re.search(PERMISSION_DENIED_REGEX, page or "", re.I) is not None

        if content or response:
            return page, headers, code

        if getRatioValue:
            return comparison(page, headers, code, getRatioValue=False, pageLength=pageLength), comparison(page, headers, code, getRatioValue=True, pageLength=pageLength)
        else:
            return comparison(page, headers, code, getRatioValue, pageLength)

def setHTTPHandlers():  # Cross-linked function
    raise NotImplementedError
