#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import httplib
import re
import socket
import time
import urllib2
import urlparse
import traceback

from extra.multipart import multipartpost
from lib.core.agent import agent
from lib.core.common import average
from lib.core.common import calculateDeltaSeconds
from lib.core.common import clearConsoleLine
from lib.core.common import cpuThrottle
from lib.core.common import getCurrentThreadData
from lib.core.common import getFilteredPageContent
from lib.core.common import unicodeToSafeHTMLValue
from lib.core.common import getUnicode
from lib.core.common import logHTTPTraffic
from lib.core.common import parseTargetUrl
from lib.core.common import readInput
from lib.core.common import removeReflectiveValues
from lib.core.common import stdev
from lib.core.common import wasLastRequestDelayed
from lib.core.convert import urlencode
from lib.core.common import urlEncodeCookieValues
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import HTTPHEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NULLCONNECTION
from lib.core.enums import PLACE
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapSyntaxException
from lib.core.settings import HTTP_SILENT_TIMEOUT
from lib.core.settings import MIN_TIME_RESPONSES
from lib.core.settings import URI_HTTP_HEADER
from lib.core.threads import getCurrentThreadData
from lib.request.basic import decodePage
from lib.request.basic import forgeHeaders
from lib.request.basic import processResponse
from lib.request.direct import direct
from lib.request.comparison import comparison
from lib.request.methodrequest import MethodRequest
from lib.utils.checkpayload import checkPayload


class Connect:
    """
    This class defines methods used to perform HTTP requests
    """

    @staticmethod
    def __getPageProxy(**kwargs):
        return Connect.getPage(**kwargs)

    @staticmethod
    def getPage(**kwargs):
        """
        This method connects to the target url or proxy and returns
        the target url page content
        """

        if conf.delay is not None and isinstance(conf.delay, (int, float)) and conf.delay > 0:
            time.sleep(conf.delay)
        elif conf.cpuThrottle:
            cpuThrottle(conf.cpuThrottle)

        threadData = getCurrentThreadData()
        threadData.lastRequestUID += 1

        # dirty hack because urllib2 just skips the other part of provided url
        # splitted with space char while urlencoding it in the later phase
        url             = kwargs.get('url',           conf.url).replace(" ", "%20")

        get             = kwargs.get('get',           None)
        post            = kwargs.get('post',          None)
        method          = kwargs.get('method',        None)
        cookie          = kwargs.get('cookie',        None)
        ua              = kwargs.get('ua',            None)
        referer         = kwargs.get('referer',       None)
        direct          = kwargs.get('direct',        False)
        multipart       = kwargs.get('multipart',     False)
        silent          = kwargs.get('silent',        False)
        raise404        = kwargs.get('raise404',      True)
        auxHeaders      = kwargs.get('auxHeaders',    None)
        response        = kwargs.get('response',      False)
        ignoreTimeout   = kwargs.get('ignoreTimeout', False)

        page            = ""
        cookieStr       = ""
        requestMsg      = "HTTP request [#%d]:\n%s " % (threadData.lastRequestUID, conf.method)
        requestMsg     += "%s" % urlparse.urlsplit(url)[2] or "/"
        responseMsg     = "HTTP response "
        requestHeaders  = ""
        responseHeaders = None
        logHeaders      = ""

        try:
            if silent:
                socket.setdefaulttimeout(HTTP_SILENT_TIMEOUT)

            if direct:
                if "?" in url:
                    url, params = url.split("?")
                    params = urlencode(params)
                    url = "%s?%s" % (url, params)
                    requestMsg += "?%s" % params

            elif multipart:
                # Needed in this form because of potential circle dependency 
                # problem (option -> update -> connect -> option)
                from lib.core.option import proxyHandler

                multipartOpener = urllib2.build_opener(proxyHandler, multipartpost.MultipartPostHandler)
                conn = multipartOpener.open(url, multipart)
                page = conn.read()
                responseHeaders = conn.info()
                responseHeaders[URI_HTTP_HEADER] = conn.geturl()
                page = decodePage(page, responseHeaders.get(HTTPHEADER.CONTENT_ENCODING), responseHeaders.get(HTTPHEADER.CONTENT_TYPE))

                return page

            else:
                if conf.parameters.has_key(PLACE.GET) and not get:
                    get = conf.parameters[PLACE.GET]

                if get:
                    url = "%s?%s" % (url, get)
                    requestMsg += "?%s" % get

                if conf.method == HTTPMETHOD.POST:
                    if conf.parameters.has_key(PLACE.POST) and not post:
                        post = conf.parameters[PLACE.POST]

            requestMsg += " %s" % httplib.HTTPConnection._http_vsn_str

            # Perform HTTP request
            headers = forgeHeaders(cookie, ua, referer)

            if conf.realTest:
                headers[HTTPHEADER.REFERER] = "%s://%s" % (conf.scheme, conf.hostname)

            if kb.authHeader:
                headers[HTTPHEADER.AUTHORIZATION] = kb.authHeader

            if kb.proxyAuthHeader:
                headers[HTTPHEADER.PROXY_AUTHORIZATION] = kb.proxyAuthHeader

            if auxHeaders:
                for key, item in auxHeaders.items():
                    headers[key] = item

            for key, item in headers.items():
                del headers[key]
                headers[unicodeToSafeHTMLValue(key)] = unicodeToSafeHTMLValue(item)

            post = unicodeToSafeHTMLValue(post)

            if method:
                req = MethodRequest(url, post, headers)
                req.set_method(method)
            else:
                req = urllib2.Request(url, post, headers)

            if not conf.dropSetCookie and conf.cj:
                for _, cookie in enumerate(conf.cj):
                    if not cookieStr:
                        cookieStr = "Cookie: "

                    cookie = getUnicode(cookie)
                    index  = cookie.index(" for ")

                    cookieStr += "%s; " % cookie[8:index]

            if not req.has_header(HTTPHEADER.ACCEPT_ENCODING):
                requestHeaders += "%s: identity\n" % HTTPHEADER.ACCEPT_ENCODING

            requestHeaders += "\n".join(["%s: %s" % (header, value) for header, value in req.header_items()])

            if not req.has_header(HTTPHEADER.COOKIE) and cookieStr:
                requestHeaders += "\n%s" % cookieStr[:-2]

            if not req.has_header(HTTPHEADER.CONNECTION):
                requestHeaders += "\n%s: close" % HTTPHEADER.CONNECTION

            requestMsg += "\n%s" % requestHeaders

            if post:
                requestMsg += "\n\n%s" % post

            requestMsg += "\n"

            logger.log(8, requestMsg)

            conn = urllib2.urlopen(req)

            if not kb.authHeader and req.has_header(HTTPHEADER.AUTHORIZATION):
                kb.authHeader = req.get_header(HTTPHEADER.AUTHORIZATION)

            if not kb.proxyAuthHeader and req.has_header(HTTPHEADER.PROXY_AUTHORIZATION):
                kb.proxyAuthHeader = req.get_header(HTTPHEADER.PROXY_AUTHORIZATION)

            if hasattr(conn, "setcookie"):
                kb.redirectSetCookie = conn.setcookie

            if hasattr(conn, "redurl") and hasattr(conn, "redcode") and not conf.redirectHandled and not conf.realTest:
                msg  = "sqlmap got a %d redirect to " % conn.redcode
                msg += "%s - What target address do you " % conn.redurl
                msg += "want to use from now on? %s " % conf.url
                msg += "(default) or provide another target address based "
                msg += "also on the redirection got from the application\n"

                while True:
                    choice = readInput(msg, default="1")

                    if not choice or choice == "1":
                        pass
                    else:
                        conf.url = choice
                        try:
                            parseTargetUrl()
                            return Connect.__getPageProxy(**kwargs)
                        except sqlmapSyntaxException:
                            continue

                    break

                conf.redirectHandled = True

            # Reset the number of connection retries
            kb.retriesCount = 0

            # Return response object
            if response:
                return conn, None

            # Get HTTP response
            page = conn.read()
            code = conn.code
            responseHeaders = conn.info()
            responseHeaders[URI_HTTP_HEADER] = conn.geturl()
            page = decodePage(page, responseHeaders.get(HTTPHEADER.CONTENT_ENCODING), responseHeaders.get(HTTPHEADER.CONTENT_TYPE))
            status = getUnicode(conn.msg)

            # Explicit closing of connection object
            if not conf.keepAlive:
                try:
                    conn.fp._sock.close()
                    conn.close()
                except Exception, msg:
                    warnMsg = "problem occured during connection closing ('%s')" % msg
                    logger.warn(warnMsg)

        except urllib2.HTTPError, e:
            page = None
            responseHeaders = None

            try:
                page = e.read()
                responseHeaders = e.info()
                responseHeaders[URI_HTTP_HEADER] = e.geturl()
                page = decodePage(page, responseHeaders.get(HTTPHEADER.CONTENT_ENCODING), responseHeaders.get(HTTPHEADER.CONTENT_TYPE))
            except socket.timeout:
                warnMsg  = "connection timed out while trying "
                warnMsg += "to get error page information (%d)" % e.code
                logger.warn(warnMsg)
                return None, None
            except:
                pass

            code = e.code
            threadData.lastHTTPError = (threadData.lastRequestUID, code)

            if code not in kb.httpErrorCodes:
                kb.httpErrorCodes[code] = 0
            kb.httpErrorCodes[code] += 1

            status = getUnicode(e.msg)
            responseMsg += "[#%d] (%d %s):\n" % (threadData.lastRequestUID, code, status)

            if responseHeaders:
                logHeaders = "\n".join(["%s: %s" % (key.capitalize() if isinstance(key, basestring) else key, getUnicode(value)) for (key, value) in responseHeaders.items()])

            logHTTPTraffic(requestMsg, "%s%s\n\n%s" % (responseMsg, logHeaders, page if isinstance(page, unicode) else getUnicode(page)))

            if conf.verbose <= 5:
                responseMsg += getUnicode(logHeaders)
            elif conf.verbose > 5:
                responseMsg += "%s\n\n%s\n" % (logHeaders, page)

            logger.log(7, responseMsg)

            if e.code == 401:
                errMsg  = "not authorized, try to provide right HTTP "
                errMsg += "authentication type and valid credentials (%d)" % code
                raise sqlmapConnectionException, errMsg
            elif e.code == 404 and raise404:
                errMsg = "page not found (%d)" % code
                raise sqlmapConnectionException, errMsg
            else:
                debugMsg = "got HTTP error code: %d (%s)" % (code, status)
                logger.debug(debugMsg)
                page = processResponse(page, responseHeaders)
                return page, responseHeaders

        except (urllib2.URLError, socket.error, socket.timeout, httplib.BadStatusLine, httplib.IncompleteRead), e:
            tbMsg = traceback.format_exc()

            if "no host given" in tbMsg:
                warnMsg = "invalid url address used (%s)" % repr(url)
                raise sqlmapSyntaxException, warnMsg
            elif "forcibly closed" in tbMsg:
                warnMsg = "connection was forcibly closed by the target url"
            elif "timed out" in tbMsg:
                warnMsg = "connection timed out to the target url"
            elif "URLError" in tbMsg or "error" in tbMsg:
                warnMsg = "unable to connect to the target url"
            elif "BadStatusLine" in tbMsg:
                warnMsg  = "the target url responded with an unknown HTTP "
                warnMsg += "status code, try to force the HTTP User-Agent "
                warnMsg += "header with option --user-agent or --random-agent"
            elif "IncompleteRead" in tbMsg:
                warnMsg = "there was an incomplete read error while retrieving data "
                warnMsg += "from the target url"
            else:
                warnMsg = "unable to connect to the target url"

            if "BadStatusLine" not in tbMsg:
                warnMsg += " or proxy"

            if "forcibly closed" in tbMsg:
                logger.critical(warnMsg)
                return None, None
            elif silent or (ignoreTimeout and "timed out" in tbMsg):
                return None, None
            elif kb.retriesCount < conf.retries and not kb.threadException and not conf.realTest:
                kb.retriesCount += 1

                warnMsg += ", sqlmap is going to retry the request"
                logger.critical(warnMsg)

                time.sleep(1)

                socket.setdefaulttimeout(conf.timeout)
                return Connect.__getPageProxy(**kwargs)
            else:
                socket.setdefaulttimeout(conf.timeout)
                raise sqlmapConnectionException, warnMsg

        socket.setdefaulttimeout(conf.timeout)

        page = processResponse(page, responseHeaders)

        responseMsg += "[#%d] (%d %s):\n" % (threadData.lastRequestUID, code, status)
        if responseHeaders:
            logHeaders = "\n".join(["%s: %s" % (key.capitalize() if isinstance(key, basestring) else key, getUnicode(value)) for (key, value) in responseHeaders.items()])

        logHTTPTraffic(requestMsg, "%s%s\n\n%s" % (responseMsg, logHeaders, page if isinstance(page, unicode) else getUnicode(page)))

        if conf.verbose <= 5:
            responseMsg += getUnicode(logHeaders)
        elif conf.verbose > 5:
            responseMsg += "%s\n\n%s\n" % (logHeaders, page)

        logger.log(7, responseMsg)

        return page, responseHeaders

    @staticmethod
    def queryPage(value=None, place=None, content=False, getRatioValue=False, silent=False, method=None, timeBasedCompare=False, noteResponseTime=True, auxHeaders=None, response=False, raise404=None):
        """
        This method calls a function to get the target url page content
        and returns its page MD5 hash or a boolean value in case of
        string match check ('--string' command line parameter)
        """

        if conf.direct:
            return direct(value, content)

        get         = None
        post        = None
        cookie      = None
        ua          = None
        referer     = None
        page        = None
        pageLength  = None
        uri         = None
        raise404    = place != PLACE.URI if raise404 is None else raise404

        if not place:
            place = kb.injection.place

        payload = agent.extractPayload(value)
        threadData = getCurrentThreadData()

        if payload:
            if kb.tamperFunctions:
                for function in kb.tamperFunctions:
                    payload = function(payload)

                value = agent.replacePayload(value, payload)

            logger.log(9, payload)

        if place == PLACE.COOKIE and conf.cookieUrlencode:
            value = agent.removePayloadDelimiters(value)
            value = urlEncodeCookieValues(value)

        elif place:
            if place in (PLACE.GET, PLACE.POST):
                # payloads in GET and/or POST need to be urlencoded 
                # throughly without safe chars (especially &, = and %)
                payload = urlencode(payload, None, True, True)
                value = agent.replacePayload(value, payload)

            value = agent.removePayloadDelimiters(value)

        if conf.checkPayload:
            checkPayload(value)

        if PLACE.GET in conf.parameters:
            get = urlencode(conf.parameters[PLACE.GET] if place != PLACE.GET or not value else value, limit=True)

        if PLACE.POST in conf.parameters:
            post = urlencode(conf.parameters[PLACE.POST] if place != PLACE.POST or not value else value)

        if PLACE.COOKIE in conf.parameters:
            cookie = conf.parameters[PLACE.COOKIE] if place != PLACE.COOKIE or not value else value

        if PLACE.UA in conf.parameters:
            ua = conf.parameters[PLACE.UA] if place != PLACE.UA or not value else value

        if PLACE.REFERER in conf.parameters:
            referer = conf.parameters[PLACE.REFERER] if place != PLACE.REFERER or not value else value

        if PLACE.URI in conf.parameters:
            uri = conf.url if place != PLACE.URI or not value else value
        else:
            uri = conf.url

        if timeBasedCompare:
            if len(kb.responseTimes) < MIN_TIME_RESPONSES:
                clearConsoleLine()

                warnMsg = "time-based comparison needs larger statistical "
                warnMsg += "model. Making a few dummy requests, please wait.."
                logger.warn(warnMsg)

                while len(kb.responseTimes) < MIN_TIME_RESPONSES:
                    Connect.queryPage(content=True)

        if conf.safUrl and conf.saFreq > 0:
            kb.queryCounter += 1
            if kb.queryCounter % conf.saFreq == 0:
                Connect.getPage(url=conf.safUrl, cookie=cookie, direct=True, silent=True, ua=ua, referer=referer)

        start = time.time()

        if kb.nullConnection and not content and not response and not timeBasedCompare:
            if kb.nullConnection == NULLCONNECTION.HEAD:
                method = HTTPMETHOD.HEAD
            elif kb.nullConnection == NULLCONNECTION.RANGE:
                if not auxHeaders:
                    auxHeaders = {}

                auxHeaders[HTTPHEADER.RANGE] = "bytes=-1"

            _, headers = Connect.getPage(url=uri, get=get, post=post, cookie=cookie, ua=ua, referer=referer, silent=silent, method=method, auxHeaders=auxHeaders, raise404=raise404)

            if kb.nullConnection == NULLCONNECTION.HEAD and HTTPHEADER.CONTENT_LENGTH in headers:
                pageLength = int(headers[HTTPHEADER.CONTENT_LENGTH])
            elif kb.nullConnection == NULLCONNECTION.RANGE and HTTPHEADER.CONTENT_RANGE in headers:
                pageLength = int(headers[HTTPHEADER.CONTENT_RANGE][headers[HTTPHEADER.CONTENT_RANGE].find('/') + 1:])

        if not pageLength:
            page, headers = Connect.getPage(url=uri, get=get, post=post, cookie=cookie, ua=ua, referer=referer, silent=silent, method=method, auxHeaders=auxHeaders, response=response, raise404=raise404, ignoreTimeout=timeBasedCompare)

        threadData.lastQueryDuration = calculateDeltaSeconds(start)

        if kb.testMode:
            kb.testQueryCount += 1

            if conf.cj:
                conf.cj.clear()

        if timeBasedCompare:
            return wasLastRequestDelayed()
        elif noteResponseTime:
            kb.responseTimes.append(threadData.lastQueryDuration)

        if content or response:
            return page, headers

        page = removeReflectiveValues(page, payload)

        if getRatioValue:
            return comparison(page, getRatioValue=False, pageLength=pageLength), comparison(page, getRatioValue=True, pageLength=pageLength)
        elif pageLength or page:
            return comparison(page, getRatioValue, pageLength)
        else:
            return False
