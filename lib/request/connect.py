#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

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



import md5
import re
import urllib2
import urlparse

from lib.contrib import multipartpost
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from lib.request.basic import forgeHeaders
from lib.request.basic import parsePage



class Connect:
    """
    This class defines methods used to perform HTTP requests
    """

    @staticmethod
    def getPage(**kwargs):
        """
        This method connects to the target url or proxy and returns
        the target url page content
        """

        url       = kwargs.get('url',       conf.url).replace(" ", "%20")
        get       = kwargs.get('get',       None)
        post      = kwargs.get('post',      None)
        cookie    = kwargs.get('cookie',    None)
        ua        = kwargs.get('ua',        None)
        direct    = kwargs.get('direct',    False)
        multipart = kwargs.get('multipart', False)

        cookieStr       = ""
        requestMsg      = "HTTP request:\n%s " % conf.method
        responseMsg     = "HTTP response "
        requestHeaders  = ""
        responseHeaders = ""

        if re.search("http[s]*://%s" % conf.hostname, url, re.I):
            requestMsg += "%s" % conf.path or "/"
        else:
            requestMsg += "%s" % urlparse.urlsplit(url)[2] or "/"

        if direct:
            if "?" in url:
                url, params = url.split("?")
                params = urlencode(params).replace("%%", "%")
                url = "%s?%s" % (url, params)
                requestMsg += "?%s" % params
        elif multipart:
                multipartOpener = urllib2.build_opener(multipartpost.MultipartPostHandler)
                conn = multipartOpener.open(url, multipart)
                page = conn.read()
                return page
        elif conf.method == "GET":
            if conf.parameters.has_key("GET") and not get:
                get = conf.parameters["GET"]

            if get:
                get = urlencode(get).replace("%%", "%")
                url = "%s?%s" % (url, get)
                requestMsg += "?%s" % get
        elif conf.method == "POST":
            if conf.parameters.has_key("POST") and not post:
                post = conf.parameters["POST"]

            post = urlencode(post).replace("%%", "%")

        requestMsg += " HTTP/1.1"

        try:
            # Perform HTTP request
            headers        = forgeHeaders(urlencode(cookie).replace("%%", "%"), ua)
            req            = urllib2.Request(url, post, headers)
            conn           = urllib2.urlopen(req)

            if "Accept-Encoding" not in req.headers:
                requestHeaders += "\nAccept-Encoding: identity"

            requestHeaders = "\n".join(["%s: %s" % (header, value) for header, value in req.header_items()])

            for _, cookie in enumerate(conf.cj):
                if not cookieStr:
                    cookieStr = "Cookie: "

                cookie = str(cookie)
                index  = cookie.index(" for ")

                cookieStr += "%s; " % cookie[8:index]

            if "Cookie" not in req.headers and cookieStr:
                requestHeaders += "\n%s" % cookieStr[:-2]
     
            if "Connection" not in req.headers:
                requestHeaders += "\nConnection: close"

            requestMsg += "\n%s" % requestHeaders

            if post:
                requestMsg += "\n%s" % post

            requestMsg += "\n"

            logger.log(9, requestMsg)

            # Get HTTP response
            page = conn.read()
            code = conn.code
            status = conn.msg
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

        except urllib2.URLError, e:
            warnMsg = "unable to connect to the target url"

            if conf.googleDork:
                warnMsg += ", skipping to next url"
                logger.warn(warnMsg)

                return None
            else:
                warnMsg += " or proxy"
                raise sqlmapConnectionException, warnMsg

        parsePage(page)
        responseMsg += "(%s - %d):\n" % (status, code)

        if conf.verbose <= 4:
            responseMsg += str(responseHeaders)
        elif conf.verbose > 4:
            responseMsg += "%s\n%s\n" % (responseHeaders, page)

        logger.log(8, responseMsg)

        return page


    @staticmethod
    def queryPage(value=None, place=None, content=False):
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

        page = Connect.getPage(get=get, post=post, cookie=cookie, ua=ua)

        if content:
            return page
        elif conf.string:
            if conf.string in page:
                return True
            else:
                return False
        else:
            return md5.new(page).hexdigest()
