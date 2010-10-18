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

from lib.contrib import multipartpost
from lib.core.common import readInput
from lib.core.common import getUnicode
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.common import sanitizeAsciiString
from lib.core.exception import sqlmapConnectionException
from lib.request.basic import decodePage
from lib.request.basic import forgeHeaders
from lib.request.basic import parseResponse
from lib.request.direct import direct
from lib.request.comparison import comparison
from lib.request.methodrequest import MethodRequest


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
            delay = 0.00001 * (conf.cpuThrottle ** 2)
            time.sleep(delay)

        url             = kwargs.get('url',        conf.url).replace(" ", "%20")
        get             = kwargs.get('get',        None)
        post            = kwargs.get('post',       None)
        method          = kwargs.get('method',     None)
        cookie          = kwargs.get('cookie',     None)
        ua              = kwargs.get('ua',         None)
        direct          = kwargs.get('direct',     False)
        multipart       = kwargs.get('multipart',  False)
        silent          = kwargs.get('silent',     False)
        raise404        = kwargs.get('raise404',   True)
        auxHeaders      = kwargs.get('auxHeaders', None)
        response        = kwargs.get('response',   False)

        page            = ""
        cookieStr       = ""
        requestMsg      = "HTTP request:\n%s " % conf.method
        requestMsg     += "%s" % urlparse.urlsplit(url)[2] or "/"
        responseMsg     = "HTTP response "
        requestHeaders  = ""
        responseHeaders = ""

        kb.lastRequestUID  += 1

        try:
            if silent:
                socket.setdefaulttimeout(3)

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
                page = decodePage(page, responseHeaders.get("Content-Encoding"), responseHeaders.get("Content-Type"))

                return page

            else:
                if conf.parameters.has_key("GET") and not get:
                    get = conf.parameters["GET"]

                if get:
                    get = urlencode(get)
                    url = "%s?%s" % (url, get)
                    requestMsg += "?%s" % get

                if conf.method == "POST":
                    if conf.parameters.has_key("POST") and not post:
                        post = conf.parameters["POST"]

            requestMsg += " HTTP/1.1"

            # Perform HTTP request
            headers = forgeHeaders(cookie, ua)

            headers["Referer"] = "%s://%s" % (conf.scheme, conf.hostname)

            if kb.authHeader:
                headers["Authorization"] = kb.authHeader

            if kb.proxyAuthHeader:
                headers["Proxy-authorization"] = kb.proxyAuthHeader

            if auxHeaders:
                for key, item in auxHeaders.items():
                    headers[key] = item

            if method:
                req = MethodRequest(url, post, headers)
                req.set_method(method)
            else:
                req = urllib2.Request(url, post, headers)

            if not req.has_header("Accept-Encoding"):
                requestHeaders += "Accept-Encoding: identity\n"

            requestHeaders += "\n".join(["%s: %s" % (header, value) for header, value in req.header_items()])

            if not conf.dropSetCookie and conf.cj:
                for _, cookie in enumerate(conf.cj):
                    if not cookieStr:
                        cookieStr = "Cookie: "

                    cookie = getUnicode(cookie)
                    index  = cookie.index(" for ")

                    cookieStr += "%s; " % cookie[8:index]

            if not req.has_header("Cookie") and cookieStr:
                requestHeaders += "\n%s" % cookieStr[:-2]

            if not req.has_header("Connection"):
                requestHeaders += "\nConnection: close"

            requestMsg += "\n%s" % requestHeaders

            if post:
                requestMsg += "\n%s" % post

            requestMsg += "\n"

            logger.log(9, requestMsg)

            conn = urllib2.urlopen(req)

            if not kb.authHeader and req.has_header("Authorization"):
                kb.authHeader = req.get_header("Authorization")

            if not kb.proxyAuthHeader and req.has_header("Proxy-authorization"):
                kb.proxyAuthHeader = req.get_header("Proxy-authorization")

            if hasattr(conn, "redurl") and hasattr(conn, "redcode") and not conf.redirectHandled:
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
                        return Connect.__getPageProxy(**kwargs)

                    break

                conf.redirectHandled = True

            # Reset the number of connection retries
            conf.retriesCount = 0
            
            # Return response object
            if response:
                return conn, None

            # Get HTTP response
            page = conn.read()
            code = conn.code
            status = conn.msg
            responseHeaders = conn.info()
            page = decodePage(page, responseHeaders.get("Content-Encoding"), responseHeaders.get("Content-Type"))

        except urllib2.HTTPError, e:
            if e.code == 401:
                errMsg  = "not authorized, try to provide right HTTP "
                errMsg += "authentication type and valid credentials"
                raise sqlmapConnectionException, errMsg
            elif e.code == 404 and raise404:
                errMsg = "page not found"
                raise sqlmapConnectionException, errMsg
            else:
                try:
                    page = e.read()
                    responseHeaders = e.info()
                except socket.timeout:
                    warnMsg  = "connection timed out while trying "
                    warnMsg += "to get error page information (%d)" % e.code
                    logger.warn(warnMsg)
                    return None, None

                code = e.code
                status = e.msg

                debugMsg = "got HTTP error code: %d (%s)" % (code, status)
                logger.debug(debugMsg)

        except (urllib2.URLError, socket.error, socket.timeout, httplib.BadStatusLine), e:
            tbMsg = traceback.format_exc()

            if "URLError" in tbMsg or "error" in tbMsg:
                warnMsg = "unable to connect to the target url"
            elif "timeout" in tbMsg:
                warnMsg = "connection timed out to the target url"
            elif "BadStatusLine" in tbMsg:
                warnMsg  = "the target url responded with an unknown HTTP "
                warnMsg += "status code, try to force the HTTP User-Agent "
                warnMsg += "header with option --user-agent or -a"
            else:
                warnMsg = "unable to connect to the target url"

            if "BadStatusLine" not in tbMsg:
                warnMsg += " or proxy"

            if silent:
                return None, None
            elif conf.retriesCount < conf.retries:
                conf.retriesCount += 1

                warnMsg += ", sqlmap is going to retry the request"
                logger.critical(warnMsg)

                time.sleep(1)

                socket.setdefaulttimeout(conf.timeout)
                return Connect.__getPageProxy(**kwargs)
            else:
                socket.setdefaulttimeout(conf.timeout)
                raise sqlmapConnectionException, warnMsg

        socket.setdefaulttimeout(conf.timeout)

        page = sanitizeAsciiString(page)
        parseResponse(page, responseHeaders)

        responseMsg += "(%s - %d):\n" % (status, code)

        if conf.verbose <= 4:
            responseMsg += getUnicode(responseHeaders.__str__())
        elif conf.verbose > 4:
            responseMsg += "%s\n%s\n" % (responseHeaders, page)

        logger.log(8, responseMsg)

        return page, responseHeaders

    @staticmethod
    def queryPage(value=None, place=None, content=False, getSeqMatcher=False, silent=False, method=None, auxHeaders=None, response=False):
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
        page        = None
        pageLength  = None
        uri         = None
        raise404    = place != "URI"

        if not place:
            place = kb.injPlace

        if kb.tamperFunctions:
            for function in kb.tamperFunctions:
                value = function(place, value)

        if "GET" in conf.parameters:
            get = conf.parameters["GET"] if place != "GET" or not value else value

        if "POST" in conf.parameters:
            post = conf.parameters["POST"] if place != "POST" or not value else value

        if "Cookie" in conf.parameters:
            cookie = conf.parameters["Cookie"] if place != "Cookie" or not value else value

        if "User-Agent" in conf.parameters:
            ua = conf.parameters["User-Agent"] if place != "User-Agent" or not value else value

        if "URI" in conf.parameters:
            uri = conf.url if place != "URI" or not value else value
        else:
            uri = conf.url

        if conf.safUrl and conf.saFreq > 0:
            kb.queryCounter += 1
            if kb.queryCounter % conf.saFreq == 0:
                Connect.getPage(url=conf.safUrl, cookie=cookie, direct=True, silent=True, ua=ua)

        if not content and not response and kb.nullConnection:
            if kb.nullConnection == "HEAD":
                method = "HEAD"
            elif kb.nullConnection == "Range":
                if not auxHeaders:
                    auxHeaders = {}

                auxHeaders["Range"] = "bytes=-1"

            _, headers = Connect.getPage(url=uri, get=get, post=post, cookie=cookie, ua=ua, silent=silent, method=method, auxHeaders=auxHeaders, raise404=raise404)

            if kb.nullConnection == "HEAD" and 'Content-Length' in headers:
                pageLength = int(headers['Content-Length'])
            elif kb.nullConnection == "Range" and 'Content-Range' in headers:
                pageLength = int(headers['Content-Range'][headers['Content-Range'].find('/') + 1:])

        if not pageLength:
            page, headers = Connect.getPage(url=uri, get=get, post=post, cookie=cookie, ua=ua, silent=silent, method=method, auxHeaders=auxHeaders, response=response, raise404=raise404)

        if content or response:
            return page, headers
        elif pageLength or page:
            return comparison(page, headers, getSeqMatcher, pageLength)
        else:
            return False
