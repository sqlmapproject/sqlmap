#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from lib.request.basic import forgeHeaders
from lib.request.basic import parseResponse
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

        if conf.delay != None and isinstance(conf.delay, (int, float)) and conf.delay > 0:
            time.sleep(conf.delay)

        url       = kwargs.get('url',       conf.url).replace(" ", "%20")
        get       = kwargs.get('get',       None)
        post      = kwargs.get('post',      None)
        cookie    = kwargs.get('cookie',    None)
        ua        = kwargs.get('ua',        None)
        direct    = kwargs.get('direct',    False)
        multipart = kwargs.get('multipart', False)
        silent    = kwargs.get('silent',    False)

        page            = ""
        cookieStr       = ""
        requestMsg      = "HTTP request:\n%s " % conf.method
        responseMsg     = "HTTP response "
        requestHeaders  = ""
        responseHeaders = ""

        if re.search("http[s]*://%s" % conf.hostname, url, re.I):
            requestMsg += "%s" % conf.path or "/"
        else:
            requestMsg += "%s" % urlparse.urlsplit(url)[2] or "/"

        if silent is True:
            socket.setdefaulttimeout(3)

        if direct:
            if "?" in url:
                url, params = url.split("?")
                params = urlencode(params).replace("%%", "%")
                url = "%s?%s" % (url, params)
                requestMsg += "?%s" % params

            if post:
                post = urlencode(post).replace("%%", "%")

        elif multipart:
            multipartOpener = urllib2.build_opener(multipartpost.MultipartPostHandler)
            conn = multipartOpener.open(url, multipart)
            page = conn.read()

            return page

        else:
            if conf.parameters.has_key("GET") and not get:
                get = conf.parameters["GET"]

            if get:
                get = urlencode(get).replace("%%", "%")
                url = "%s?%s" % (url, get)
                requestMsg += "?%s" % get

            if conf.method == "POST":
                if conf.parameters.has_key("POST") and not post:
                    post = conf.parameters["POST"]

                post = urlencode(post).replace("%%", "%")

        requestMsg += " HTTP/1.1"

        if cookie:
            # TODO: sure about encoding the cookie?
            #cookie = urlencode(cookie).replace("%%", "%")
            cookie = cookie.replace("%%", "%")

        try:
            # Perform HTTP request
            headers        = forgeHeaders(cookie, ua)
            req            = urllib2.Request(url, post, headers)
            conn           = urllib2.urlopen(req)

            # Reset the number of connection retries
            conf.retriesCount = 0

            if not req.has_header("Accept-Encoding"):
                requestHeaders += "\nAccept-Encoding: identity"

            requestHeaders = "\n".join(["%s: %s" % (header, value) for header, value in req.header_items()])

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

        except urllib2.HTTPError, e:
            if e.code == 401:
                exceptionMsg  = "not authorized, try to provide right HTTP "
                exceptionMsg += "authentication type and valid credentials"
                raise sqlmapConnectionException, exceptionMsg
            else:
                page = e.read()
                code = e.code
                status = e.msg
                responseHeaders = e.info()

        except (urllib2.URLError, socket.error, socket.timeout, httplib.BadStatusLine), _:
            tbMsg = traceback.format_exc()

            if "URLError" in tbMsg or "error" in tbMsg:
                warnMsg = "unable to connect to the target url"

            elif "timeout" in tbMsg:
                warnMsg = "connection timed out to the target url"

            elif "BadStatusLine" in tbMsg:
                warnMsg  = "the target url responded with an unknown HTTP "
                warnMsg += "status code, try to force the HTTP User-Agent "
                warnMsg += "header with option --user-agent or -a"

            if "BadStatusLine" not in tbMsg:
                warnMsg += " or proxy"

            if conf.multipleTargets:
                warnMsg += ", skipping to next url"
                logger.warn(warnMsg)

                return None, None

            if silent is True:
                return None, None

            elif conf.retriesCount < conf.retries:
                conf.retriesCount += 1

                warnMsg += ", sqlmap is going to retry the request"
                logger.warn(warnMsg)

                time.sleep(1)

                socket.setdefaulttimeout(conf.timeout)
                return Connect.__getPageProxy(url=url, get=get, post=post, cookie=cookie, ua=ua, direct=direct, multipart=multipart, silent=silent)

            else:
                socket.setdefaulttimeout(conf.timeout)
                raise sqlmapConnectionException, warnMsg

        socket.setdefaulttimeout(conf.timeout)

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

        page, headers = Connect.getPage(get=get, post=post, cookie=cookie, ua=ua, silent=silent)

        if content:
            return page, headers
        elif page:
            return comparison(page, headers, getSeqMatcher)
        else:
            return False
