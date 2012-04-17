#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import httplib
import re
import socket
import time
import urllib2
import urlparse
import traceback

from extra.safe2bin.safe2bin import safecharencode
from extra.socks.socks import ProxyError
from extra.multipart import multipartpost

from lib.core.agent import agent
from lib.core.common import asciifyUrl
from lib.core.common import calculateDeltaSeconds
from lib.core.common import clearConsoleLine
from lib.core.common import cpuThrottle
from lib.core.common import evaluateCode
from lib.core.common import extractRegexResult
from lib.core.common import getCurrentThreadData
from lib.core.common import getHostHeader
from lib.core.common import getUnicode
from lib.core.common import logHTTPTraffic
from lib.core.common import randomizeParameterValue
from lib.core.common import readInput
from lib.core.common import removeReflectiveValues
from lib.core.common import singleTimeWarnMessage
from lib.core.common import stdev
from lib.core.common import urlEncodeCookieValues
from lib.core.common import wasLastRequestDelayed
from lib.core.convert import unicodeencode
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import HTTPHEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NULLCONNECTION
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.enums import REDIRECTION
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapSyntaxException
from lib.core.settings import CUSTOM_INJECTION_MARK_CHAR
from lib.core.settings import HTTP_ACCEPT_HEADER_VALUE
from lib.core.settings import HTTP_SILENT_TIMEOUT
from lib.core.settings import MAX_CONNECTION_CHUNK_SIZE
from lib.core.settings import META_REFRESH_REGEX
from lib.core.settings import MIN_TIME_RESPONSES
from lib.core.settings import IS_WIN
from lib.core.settings import LARGE_CHUNK_TRIM_MARKER
from lib.core.settings import UNENCODED_ORIGINAL_VALUE
from lib.core.settings import URI_HTTP_HEADER
from lib.core.settings import WARN_TIME_STDEV
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
    def __retryProxy(**kwargs):
        threadData = getCurrentThreadData()
        threadData.retriesCount += 1

        if kb.testMode and kb.previousMethod == PAYLOAD.METHOD.TIME:
            # timed based payloads can cause web server unresponsiveness
            # if the injectable piece of code is some kind of JOIN-like query
            warnMsg = "most probably web server instance hasn't recovered yet "
            warnMsg += "from previous timed based payload. If the problem "
            warnMsg += "persists please wait for few minutes and rerun "
            warnMsg += "without flag T in option '--technique' "
            warnMsg += "(e.g. --flush-session --technique=BEUS) or try to "
            warnMsg += "lower the value of option '--time-sec' (e.g. --time-sec=2)"
            singleTimeWarnMessage(warnMsg)
        elif kb.originalPage is None:
            if conf.tor:
                warnMsg = "please make sure that you have "
                warnMsg += "Tor installed and running so "
                warnMsg += "you could successfully use "
                warnMsg += "switch '--tor' "
                if IS_WIN:
                    warnMsg += "(e.g. https://www.torproject.org/download/download.html.en)"
                else:
                    warnMsg += "(e.g. https://help.ubuntu.com/community/Tor)"
            else:
                warnMsg = "if the problem persists please check that the provided "
                warnMsg += "target url is valid. If it is, you can try to rerun "
                warnMsg += "with the switch '--random-agent' turned on "
                warnMsg += "and/or proxy switches (--ignore-proxy, --proxy,...)"
            singleTimeWarnMessage(warnMsg)
        elif conf.threads > 1:
            warnMsg = "if the problem persists please try to lower "
            warnMsg += "the number of used threads (--threads)"
            singleTimeWarnMessage(warnMsg)

        time.sleep(1)

        kwargs['retrying'] = True
        return Connect.__getPageProxy(**kwargs)

    @staticmethod
    def __connReadProxy(conn):
        retVal = ""
        while True:
            _ = conn.read(MAX_CONNECTION_CHUNK_SIZE)
            if len(_) == MAX_CONNECTION_CHUNK_SIZE:
                warnMsg = "large response detected. This could take a while"
                singleTimeWarnMessage(warnMsg)
                _ = re.sub(r"(?si)%s.+?%s" % (kb.chars.stop, kb.chars.start), "%s%s%s" % (kb.chars.stop, LARGE_CHUNK_TRIM_MARKER, kb.chars.start), _)
                retVal += _
            else:
                retVal += _
                break
        return retVal

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

        url = kwargs.get('url',                     conf.url)
        get = kwargs.get('get',                     None)
        post = kwargs.get('post',                   None)
        method = kwargs.get('method',               None)
        cookie = kwargs.get('cookie',               None)
        ua = kwargs.get('ua',                       None)
        referer = kwargs.get('referer',             None)
        host = kwargs.get('host',                   conf.host)
        direct = kwargs.get('direct',               False)
        multipart = kwargs.get('multipart',         False)
        silent = kwargs.get('silent',               False)
        raise404 = kwargs.get('raise404',           True)
        auxHeaders = kwargs.get('auxHeaders',       None)
        response = kwargs.get('response',           False)
        ignoreTimeout = kwargs.get('ignoreTimeout', kb.ignoreTimeout)
        refreshing = kwargs.get('refreshing',       False)
        retrying = kwargs.get('retrying',           False)
        crawling = kwargs.get('crawling',           False)

        if not urlparse.urlsplit(url).netloc:
            url = urlparse.urljoin(conf.url, url)

        # flag to know if we are dealing with the same target host
        target = reduce(lambda x, y: x == y, map(lambda x: urlparse.urlparse(x).netloc.split(':')[0], [url, conf.url or ""]))

        if not retrying:
            # Reset the number of connection retries
            threadData.retriesCount = 0

        # fix for known issue when urllib2 just skips the other part of provided
        # url splitted with space char while urlencoding it in the later phase
        url = url.replace(" ", "%20")

        code = None
        page = None
        requestMsg = u"HTTP request [#%d]:\n%s " % (threadData.lastRequestUID, method or (HTTPMETHOD.POST if post else HTTPMETHOD.GET))
        requestMsg += "%s" % urlparse.urlsplit(url)[2] or "/"
        responseMsg = u"HTTP response "
        requestHeaders = u""
        responseHeaders = None
        logHeaders = u""
        skipLogTraffic = False

        raise404 = raise404 and not kb.ignoreNotFound

        # support for non-latin (e.g. cyrillic) URLs as urllib/urllib2 doesn't
        # support those by default
        url = asciifyUrl(url)

        # fix for known issues when using url in unicode format
        # (e.g. UnicodeDecodeError: "url = url + '?' + query" in redirect case)
        url = unicodeencode(url)

        try:
            if silent:
                socket.setdefaulttimeout(HTTP_SILENT_TIMEOUT)
            else:
                socket.setdefaulttimeout(conf.timeout)

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
                conn = multipartOpener.open(unicodeencode(url), multipart)
                page = Connect.__connReadProxy(conn)
                responseHeaders = conn.info()
                responseHeaders[URI_HTTP_HEADER] = conn.geturl()
                page = decodePage(page, responseHeaders.get(HTTPHEADER.CONTENT_ENCODING), responseHeaders.get(HTTPHEADER.CONTENT_TYPE))

                return page

            elif any ([refreshing, crawling]):
                pass

            elif target:
                if conf.parameters.has_key(PLACE.GET) and not get:
                    get = conf.parameters[PLACE.GET]

                if get:
                    url = "%s?%s" % (url, get)
                    requestMsg += "?%s" % get

                if conf.method == HTTPMETHOD.POST and not post:
                    for place in (PLACE.POST, PLACE.SOAP):
                        if conf.parameters.has_key(place):
                            post = conf.parameters[place]
                            break

            elif get:
                url = "%s?%s" % (url, get)
                requestMsg += "?%s" % get

            requestMsg += " %s" % httplib.HTTPConnection._http_vsn_str

            # Prepare HTTP headers
            headers = forgeHeaders({ HTTPHEADER.COOKIE: cookie, HTTPHEADER.USER_AGENT: ua, HTTPHEADER.REFERER: referer })

            if conf.realTest:
                headers[HTTPHEADER.REFERER] = "%s://%s" % (conf.scheme, conf.hostname)

            if kb.authHeader:
                headers[HTTPHEADER.AUTHORIZATION] = kb.authHeader

            if kb.proxyAuthHeader:
                headers[HTTPHEADER.PROXY_AUTHORIZATION] = kb.proxyAuthHeader

            headers[HTTPHEADER.ACCEPT] = HTTP_ACCEPT_HEADER_VALUE

            headers[HTTPHEADER.HOST] = host or getHostHeader(url)

            if auxHeaders:
                for key, item in auxHeaders.items():
                    headers[key] = item

            for key, item in headers.items():
                del headers[key]
                headers[unicodeencode(key, kb.pageEncoding)] = unicodeencode(item, kb.pageEncoding)

            post = unicodeencode(post, kb.pageEncoding)

            if method:
                req = MethodRequest(url, post, headers)
                req.set_method(method)
            else:
                req = urllib2.Request(url, post, headers)

            if not req.has_header(HTTPHEADER.ACCEPT_ENCODING):
                requestHeaders += "%s: identity\n" % HTTPHEADER.ACCEPT_ENCODING

            requestHeaders += "\n".join("%s: %s" % (key.capitalize() if isinstance(key, basestring) else key, getUnicode(value)) for (key, value) in req.header_items())

            if not req.has_header(HTTPHEADER.COOKIE) and conf.cj:
                conf.cj._policy._now = conf.cj._now = int(time.time())
                cookies = conf.cj._cookies_for_request(req)
                requestHeaders += "\n%s" % ("Cookie: %s" % ";".join("%s=%s" % (getUnicode(cookie.name), getUnicode(cookie.value)) for cookie in cookies))

            if not req.has_header(HTTPHEADER.CONNECTION):
                requestHeaders += "\n%s: close" % HTTPHEADER.CONNECTION

            requestMsg += "\n%s" % requestHeaders

            if post:
                requestMsg += "\n\n%s" % getUnicode(post)

            requestMsg += "\n"

            threadData.lastRequestMsg = requestMsg

            logger.log(CUSTOM_LOGGING.TRAFFIC_OUT, requestMsg)

            conn = urllib2.urlopen(req)

            if not kb.authHeader and req.has_header(HTTPHEADER.AUTHORIZATION):
                kb.authHeader = req.get_header(HTTPHEADER.AUTHORIZATION)

            if not kb.proxyAuthHeader and req.has_header(HTTPHEADER.PROXY_AUTHORIZATION):
                kb.proxyAuthHeader = req.get_header(HTTPHEADER.PROXY_AUTHORIZATION)

            # Return response object
            if response:
                return conn, None, None

            # Get HTTP response
            if hasattr(conn, 'redurl'):
                page = threadData.lastRedirectMsg[1] if kb.redirectChoice == REDIRECTION.NO\
                  else Connect.__connReadProxy(conn)
                skipLogTraffic = kb.redirectChoice == REDIRECTION.NO
                code = conn.redcode
            else:
                page = Connect.__connReadProxy(conn)

            code = code or conn.code
            responseHeaders = conn.info()
            responseHeaders[URI_HTTP_HEADER] = conn.geturl()
            page = decodePage(page, responseHeaders.get(HTTPHEADER.CONTENT_ENCODING), responseHeaders.get(HTTPHEADER.CONTENT_TYPE))
            status = getUnicode(conn.msg)

            if extractRegexResult(META_REFRESH_REGEX, page, re.DOTALL | re.IGNORECASE) and not refreshing:
                url = extractRegexResult(META_REFRESH_REGEX, page, re.DOTALL | re.IGNORECASE)

                debugMsg = "got HTML meta refresh header"
                logger.debug(debugMsg)

                if kb.alwaysRefresh is None:
                    msg = "sqlmap got a refresh request "
                    msg += "(redirect like response common to login pages). "
                    msg += "Do you want to apply the refresh "
                    msg += "from now on (or stay on the original page)? [Y/n]"
                    choice = readInput(msg, default="Y")

                    kb.alwaysRefresh = choice not in ("n", "N")

                if kb.alwaysRefresh:
                    if url.lower().startswith('http://'):
                        kwargs['url'] = url
                    else:
                        kwargs['url'] = conf.url[:conf.url.rfind('/')+1] + url

                    threadData.lastRedirectMsg = (threadData.lastRequestUID, page)
                    kwargs['refreshing'] = True
                    kwargs['get'] = None
                    kwargs['post'] = None

                    try:
                        return Connect.__getPageProxy(**kwargs)
                    except sqlmapSyntaxException:
                        pass

            # Explicit closing of connection object
            if not conf.keepAlive:
                try:
                    if hasattr(conn.fp, '_sock'):
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
                warnMsg = "connection timed out while trying "
                warnMsg += "to get error page information (%d)" % e.code
                logger.warn(warnMsg)
                return None, None, None
            except KeyboardInterrupt:
                raise
            except:
                pass
            finally:
                page = page if isinstance(page, unicode) else getUnicode(page)

            code = e.code
            threadData.lastHTTPError = (threadData.lastRequestUID, code)

            kb.httpErrorCodes[code] = kb.httpErrorCodes.get(code, 0) + 1

            status = getUnicode(e.msg)
            responseMsg += "[#%d] (%d %s):\n" % (threadData.lastRequestUID, code, status)

            if responseHeaders:
                logHeaders = "\n".join("%s: %s" % (key.capitalize() if isinstance(key, basestring) else key, getUnicode(value)) for (key, value) in responseHeaders.items())

            logHTTPTraffic(requestMsg, "%s%s\n\n%s" % (responseMsg, logHeaders, page))

            skipLogTraffic = True

            if conf.verbose <= 5:
                responseMsg += getUnicode(logHeaders)
            elif conf.verbose > 5:
                responseMsg += "%s\n\n%s\n" % (logHeaders, page)

            logger.log(CUSTOM_LOGGING.TRAFFIC_IN, responseMsg)

            if e.code == httplib.UNAUTHORIZED:
                errMsg = "not authorized, try to provide right HTTP "
                errMsg += "authentication type and valid credentials (%d)" % code
                raise sqlmapConnectionException, errMsg
            elif e.code == httplib.NOT_FOUND:
                if raise404:
                    errMsg = "page not found (%d)" % code
                    raise sqlmapConnectionException, errMsg
                else:
                    debugMsg = "page not found (%d)" % code
                    logger.debug(debugMsg)
                    processResponse(page, responseHeaders)
            elif e.code == httplib.GATEWAY_TIMEOUT:
                if ignoreTimeout:
                    return None, None, None
                else:
                    warnMsg = "unable to connect to the target url (%d - %s)" % (e.code, httplib.responses[e.code])
                    if threadData.retriesCount < conf.retries and not kb.threadException and not conf.realTest:
                        warnMsg += ", sqlmap is going to retry the request"
                        logger.critical(warnMsg)
                        return Connect.__retryProxy(**kwargs)
                    elif kb.testMode:
                        logger.critical(warnMsg)
                        return None, None, None
                    else:
                        raise sqlmapConnectionException, warnMsg
            else:
                debugMsg = "got HTTP error code: %d (%s)" % (code, status)
                logger.debug(debugMsg)

        except (urllib2.URLError, socket.error, socket.timeout, httplib.BadStatusLine, httplib.IncompleteRead, ProxyError), e:
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
                warnMsg = "the target url responded with an unknown HTTP "
                warnMsg += "status code, try to force the HTTP User-Agent "
                warnMsg += "header with option '--user-agent' or switch '--random-agent'"
            elif "IncompleteRead" in tbMsg:
                warnMsg = "there was an incomplete read error while retrieving data "
                warnMsg += "from the target url"
            else:
                warnMsg = "unable to connect to the target url"

            if "BadStatusLine" not in tbMsg:
                warnMsg += " or proxy"

            if "forcibly closed" in tbMsg:
                logger.critical(warnMsg)
                return None, None, None
            elif silent or (ignoreTimeout and any(_ in tbMsg for _ in ("timed out", "IncompleteRead"))):
                return None, None, None
            elif threadData.retriesCount < conf.retries and not kb.threadException and not conf.realTest:
                warnMsg += ", sqlmap is going to retry the request"
                logger.critical(warnMsg)
                return Connect.__retryProxy(**kwargs)
            elif kb.testMode:
                logger.critical(warnMsg)
                return None, None, None
            else:
                raise sqlmapConnectionException, warnMsg

        finally:
            page = page if isinstance(page, unicode) else getUnicode(page)
            socket.setdefaulttimeout(conf.timeout)

        processResponse(page, responseHeaders)

        responseMsg += "[#%d] (%d %s):\n" % (threadData.lastRequestUID, code, status)
        if responseHeaders:
            logHeaders = "\n".join("%s: %s" % (key.capitalize() if isinstance(key, basestring) else key, getUnicode(value)) for (key, value) in responseHeaders.items())

        if not skipLogTraffic:
            logHTTPTraffic(requestMsg, "%s%s\n\n%s" % (responseMsg, logHeaders, page))

        if conf.verbose <= 5:
            responseMsg += getUnicode(logHeaders)
        elif conf.verbose > 5:
            responseMsg += "%s\n\n%s\n" % (logHeaders, page)

        logger.log(CUSTOM_LOGGING.TRAFFIC_IN, responseMsg)

        return page, responseHeaders, code

    @staticmethod
    def queryPage(value=None, place=None, content=False, getRatioValue=False, silent=False, method=None, timeBasedCompare=False, noteResponseTime=True, auxHeaders=None, response=False, raise404=None, removeReflection=True):
        """
        This method calls a function to get the target url page content
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

        raise404 = place != PLACE.URI if raise404 is None else raise404

        value = agent.adjustSleepTime(value)
        payload = agent.extractPayload(value)
        threadData = getCurrentThreadData()

        if payload:
            if kb.tamperFunctions:
                for function in kb.tamperFunctions:
                    payload = function(payload)

                value = agent.replacePayload(value, payload)

            logger.log(CUSTOM_LOGGING.PAYLOAD, safecharencode(payload))

        if place == PLACE.COOKIE and conf.cookieUrlencode:
            value = agent.removePayloadDelimiters(value)
            value = urlEncodeCookieValues(value)

        elif place:
            if place in (PLACE.GET, PLACE.POST, PLACE.URI, PLACE.CUSTOM_POST):
                # payloads in GET and/or POST need to be urlencoded
                # throughly without safe chars (especially & and =)
                # addendum: as we support url encoding in tampering
                # functions therefore we need to use % as a safe char
                if place != PLACE.URI or (value and payload and '?' in value and value.find('?') < value.find(payload)):
                    payload = urlencode(payload, "%", False, True)
                    value = agent.replacePayload(value, payload)
            elif place == PLACE.SOAP:
                # payloads in SOAP should have chars > and < replaced
                # with their HTML encoded counterparts
                payload = payload.replace('>', '&gt;').replace('<', '&lt;')
                value = agent.replacePayload(value, payload)

            value = agent.removePayloadDelimiters(value)

        if conf.checkPayload:
            checkPayload(value)

        if PLACE.GET in conf.parameters:
            get = conf.parameters[PLACE.GET] if place != PLACE.GET or not value else value

        if PLACE.POST in conf.parameters:
            post = conf.parameters[PLACE.POST] if place != PLACE.POST or not value else value

        if PLACE.CUSTOM_POST in conf.parameters:
            post = conf.parameters[PLACE.CUSTOM_POST].replace(CUSTOM_INJECTION_MARK_CHAR, "") if place != PLACE.CUSTOM_POST or not value else value

        if PLACE.SOAP in conf.parameters:
            post = conf.parameters[PLACE.SOAP] if place != PLACE.SOAP or not value else value

        if PLACE.COOKIE in conf.parameters:
            cookie = conf.parameters[PLACE.COOKIE] if place != PLACE.COOKIE or not value else value

        if PLACE.UA in conf.parameters:
            ua = conf.parameters[PLACE.UA] if place != PLACE.UA or not value else value

        if PLACE.REFERER in conf.parameters:
            referer = conf.parameters[PLACE.REFERER] if place != PLACE.REFERER or not value else value

        if PLACE.HOST in conf.parameters:
            host = conf.parameters[PLACE.HOST] if place != PLACE.HOST or not value else value

        if PLACE.URI in conf.parameters:
            uri = conf.url if place != PLACE.URI or not value else value
        else:
            uri = conf.url

        if conf.rParam:
            def _randomizeParameter(paramString, randomParameter):
                retVal = paramString
                match = re.search("%s=(?P<value>[^&;]+)" % randomParameter, paramString)
                if match:
                    origValue = match.group("value")
                    retVal = re.sub("%s=[^&;]+" % randomParameter, "%s=%s" % (randomParameter, randomizeParameterValue(origValue)), paramString)
                return retVal

            for randomParameter in conf.rParam:
                for item in [PLACE.GET, PLACE.POST, PLACE.COOKIE]:
                    if item in conf.parameters:
                        if item == PLACE.GET and get:
                            get = _randomizeParameter(get, randomParameter)
                        elif item == PLACE.POST and post:
                            post = _randomizeParameter(post, randomParameter)
                        elif item == PLACE.COOKIE and cookie:
                            cookie = _randomizeParameter(cookie, randomParameter)

        if conf.evalCode:
            delimiter = conf.pDel or "&"
            variables = {}
            originals = {}

            for item in filter(None, (get, post)):
                for part in item.split(delimiter):
                    if '=' in part:
                        name, value = part.split('=', 1)
                        evaluateCode("%s='%s'" % (name, value), variables)

            originals.update(variables)
            evaluateCode(conf.evalCode, variables)

            for name, value in variables.items():
                if name != "__builtins__" and originals.get(name, "") != value:
                    if isinstance(value, (basestring, int)):
                        value = unicode(value)
                        if '%s=' % name in (get or ""):
                            get = re.sub("((\A|\W)%s=)([^%s]+)" % (name, delimiter), "\g<1>%s" % value, get)
                        elif '%s=' % name in (post or ""):
                            post = re.sub("((\A|\W)%s=)([^%s]+)" % (name, delimiter), "\g<1>%s" % value, post)
                        elif post:
                            post += "%s%s=%s" % (delimiter, name, value)
                        else:
                            get += "%s%s=%s" % (delimiter, name, value)

        get = urlencode(get, limit=True)
        if post and place != PLACE.POST and hasattr(post, UNENCODED_ORIGINAL_VALUE):
            post = getattr(post, UNENCODED_ORIGINAL_VALUE)
        else:
            post = urlencode(post)

        if timeBasedCompare:
            if len(kb.responseTimes) < MIN_TIME_RESPONSES:
                clearConsoleLine()

                if conf.tor:
                    warnMsg = "it's highly recommended to avoid usage of switch '--tor' for "
                    warnMsg += "time-based injections because of its high latency time"
                    singleTimeWarnMessage(warnMsg)

                warnMsg = "time-based comparison needs larger statistical "
                warnMsg += "model. Making a few dummy requests, please wait.."
                singleTimeWarnMessage(warnMsg)

                while len(kb.responseTimes) < MIN_TIME_RESPONSES:
                    Connect.queryPage(content=True)

                deviation = stdev(kb.responseTimes)

                if deviation > WARN_TIME_STDEV:
                    kb.adjustTimeDelay = False

                    warnMsg = "there is considerable lagging "
                    warnMsg += "in connection response(s). Please use as high "
                    warnMsg += "value for option '--time-sec' as possible (e.g. "
                    warnMsg += "%d or more)" % (conf.timeSec * 2)
                    logger.critical(warnMsg)
            elif not kb.testMode:
                warnMsg = "it is very important not to stress the network adapter's "
                warnMsg += "bandwidth during usage of time-based queries"
                singleTimeWarnMessage(warnMsg)

        if conf.safUrl and conf.saFreq > 0:
            kb.queryCounter += 1
            if kb.queryCounter % conf.saFreq == 0:
                Connect.getPage(url=conf.safUrl, cookie=cookie, direct=True, silent=True, ua=ua, referer=referer, host=host)

        start = time.time()

        if kb.nullConnection and not content and not response and not timeBasedCompare:
            if kb.nullConnection == NULLCONNECTION.HEAD:
                method = HTTPMETHOD.HEAD
            elif kb.nullConnection == NULLCONNECTION.RANGE:
                if not auxHeaders:
                    auxHeaders = {}

                auxHeaders[HTTPHEADER.RANGE] = "bytes=-1"

            _, headers, code = Connect.getPage(url=uri, get=get, post=post, cookie=cookie, ua=ua, referer=referer, host=host, silent=silent, method=method, auxHeaders=auxHeaders, raise404=raise404)

            if headers:
                if kb.nullConnection == NULLCONNECTION.HEAD and HTTPHEADER.CONTENT_LENGTH in headers:
                    pageLength = int(headers[HTTPHEADER.CONTENT_LENGTH])
                elif kb.nullConnection == NULLCONNECTION.RANGE and HTTPHEADER.CONTENT_RANGE in headers:
                    pageLength = int(headers[HTTPHEADER.CONTENT_RANGE][headers[HTTPHEADER.CONTENT_RANGE].find('/') + 1:])

        if not pageLength:
            page, headers, code = Connect.getPage(url=uri, get=get, post=post, cookie=cookie, ua=ua, referer=referer, host=host, silent=silent, method=method, auxHeaders=auxHeaders, response=response, raise404=raise404, ignoreTimeout=timeBasedCompare)

        threadData.lastQueryDuration = calculateDeltaSeconds(start)

        kb.originalCode = kb.originalCode or code

        if kb.testMode:
            kb.testQueryCount += 1

        if timeBasedCompare:
            return wasLastRequestDelayed()
        elif noteResponseTime:
            kb.responseTimes.append(threadData.lastQueryDuration)

        if not response and removeReflection:
            page = removeReflectiveValues(page, payload)

        kb.maxConnectionsFlag = re.search(r"max.+connections", page or "", re.I) is not None
        kb.permissionFlag = re.search(r"(command|permission|access)\s*(was|is)?\s*denied", page or "", re.I) is not None

        if content or response:
            return page, headers

        if getRatioValue:
            return comparison(page, headers, code, getRatioValue=False, pageLength=pageLength), comparison(page, headers, code, getRatioValue=True, pageLength=pageLength)
        elif pageLength or page:
            return comparison(page, headers, code, getRatioValue, pageLength)
        else:
            return False
