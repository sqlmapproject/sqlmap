#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.common import sanitizeAsciiString
from lib.core.exception import sqlmapConnectionException
from lib.core.settings import SQL_STATEMENTS
from lib.request.basic import decodePage
from lib.request.basic import forgeHeaders
from lib.request.basic import parseResponse
from lib.request.direct import direct
from lib.request.comparison import comparison


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

        url       = kwargs.get('url',       conf.url).replace(" ", "%20")
        get       = kwargs.get('get',       None)
        post      = kwargs.get('post',      None)
        cookie    = kwargs.get('cookie',    None)
        ua        = kwargs.get('ua',        None)
        direct    = kwargs.get('direct',    False)
        multipart = kwargs.get('multipart', False)
        silent    = kwargs.get('silent',    False)
        raise404  = kwargs.get('raise404',  True)

        page            = ""
        cookieStr       = ""
        requestMsg      = "HTTP request:\n%s " % conf.method
        requestMsg     += "%s" % urlparse.urlsplit(url)[2] or "/"
        responseMsg     = "HTTP response "
        requestHeaders  = ""
        responseHeaders = ""

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
                #needed in this form because of potential circle dependency problem (option -> update -> connect -> option)
                from lib.core.option import proxyHandler
                
                multipartOpener = urllib2.build_opener(proxyHandler, multipartpost.MultipartPostHandler)
                conn = multipartOpener.open(url, multipart)
                page = conn.read()            
                responseHeaders = conn.info()
    
                encoding = responseHeaders.get("Content-Encoding")
                page = decodePage(page, encoding)
    
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
            headers        = forgeHeaders(cookie, ua)
            req            = urllib2.Request(url, post, headers)
            conn           = urllib2.urlopen(req)

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

                    break

                conf.redirectHandled = True

                return Connect.__getPageProxy(**kwargs)

            # Reset the number of connection retries
            conf.retriesCount = 0

            if not req.has_header("Accept-Encoding"):
                requestHeaders += "\nAccept-Encoding: identity"

            requestHeaders = "\n".join(["%s: %s" % (header, value) for header, value in req.header_items()])

            if not conf.dropSetCookie and conf.cj:
                for _, cookie in enumerate(conf.cj):
                    if not cookieStr:
                        cookieStr = "Cookie: "
    
                    cookie = str(cookie)
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

            # Get HTTP response
            page            = conn.read()
            code            = conn.code
            status          = conn.msg
            responseHeaders = conn.info()

            encoding = responseHeaders.get("Content-Encoding")
            page = decodePage(page, encoding)

        except urllib2.HTTPError, e:
            if e.code == 401:
                errMsg  = "not authorized, try to provide right HTTP "
                errMsg += "authentication type and valid credentials"
                raise sqlmapConnectionException, errMsg
            elif e.code == 404 and raise404:
                errMsg = "page not found"
                raise sqlmapConnectionException, errMsg
            else:
                page = e.read()
                code = e.code
                status = e.msg
                responseHeaders = e.info()

                debugMsg = "got HTTP error code: %d" % code
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
                logger.warn(warnMsg)

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
            responseMsg += str(responseHeaders)
        elif conf.verbose > 4:
            responseMsg += "%s\n%s\n" % (responseHeaders, page)
        
        logger.log(8, responseMsg)

        return page, responseHeaders

    @staticmethod
    def queryPage(value=None, place=None, content=False, getSeqMatcher=False, silent=False):
        """
        This method calls a function to get the target url page content
        and returns its page MD5 hash or a boolean value in case of
        string match check ('--string' command line parameter)
        """

        if conf.direct:
            return direct(value, content)

        get    = None
        post   = None
        cookie = None
        ua     = None

        if not place:
            place = kb.injPlace

        if conf.parameters.has_key("GET"):
            if place == "GET" and value:
                get = value
            else:
                get = conf.parameters["GET"]

        if conf.parameters.has_key("POST"):
            if place == "POST" and value:
                post = value
            else:
                post = conf.parameters["POST"]

        if conf.parameters.has_key("Cookie"):
            if place == "Cookie" and value:
                cookie = value
            else:
                cookie = conf.parameters["Cookie"]

        if conf.parameters.has_key("User-Agent"):
            if place == "User-Agent" and value:
                ua = value
            else:
                ua = conf.parameters["User-Agent"]
        
        if conf.safUrl and conf.saFreq > 0:
            kb.queryCounter += 1
            if kb.queryCounter % conf.saFreq == 0:
                Connect.getPage(url=conf.safUrl, cookie=cookie, direct=True, silent=True, ua=ua)
        
        page, headers = Connect.getPage(get=get, post=post, cookie=cookie, ua=ua, silent=silent)

        if content:
            return page, headers
        elif page:
            return comparison(page, headers, getSeqMatcher)
        else:
            return False
