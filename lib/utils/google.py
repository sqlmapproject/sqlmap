#!/usr/bin/env python

"""
Copyright (c) 2006-2015 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import cookielib
import httplib
import re
import socket
import urllib
import urllib2

from lib.core.common import getSafeExString
from lib.core.common import getUnicode
from lib.core.common import readInput
from lib.core.common import urlencode
from lib.core.data import conf
from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import HTTP_HEADER
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapGenericException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import DUMMY_SEARCH_USER_AGENT
from lib.core.settings import DUCKDUCKGO_REGEX
from lib.core.settings import DISCONNECT_SEARCH_REGEX
from lib.core.settings import GOOGLE_REGEX
from lib.core.settings import HTTP_ACCEPT_ENCODING_HEADER_VALUE
from lib.core.settings import UNICODE_ENCODING
from lib.request.basic import decodePage
from lib.request.httpshandler import HTTPSHandler

class Google(object):
    """
    This class defines methods used to perform Google dorking (command
    line option '-g <google dork>')
    """

    def __init__(self, handlers):
        self._cj = cookielib.CookieJar()

        handlers.append(urllib2.HTTPCookieProcessor(self._cj))
        handlers.append(HTTPSHandler())

        self.opener = urllib2.build_opener(*handlers)
        self.opener.addheaders = conf.httpHeaders

        try:
            conn = self.opener.open("http://www.google.com/ncr")
            conn.info()  # retrieve session cookie
        except Exception, ex:
            errMsg = "unable to connect to Google ('%s')" % getSafeExString(ex)
            raise SqlmapConnectionException(errMsg)

    def search(self, dork):
        """
        This method performs the effective search on Google providing
        the google dork and the Google session cookie
        """

        gpage = conf.googlePage if conf.googlePage > 1 else 1
        logger.info("using Google result page #%d" % gpage)

        if not dork:
            return None

        url = "http://www.google.com/search?"
        url += "q=%s&" % urlencode(dork, convall=True)
        url += "num=100&hl=en&complete=0&safe=off&filter=0&btnG=Search"
        url += "&start=%d" % ((gpage - 1) * 100)

        try:
            conn = self.opener.open(url)

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
        except (urllib2.URLError, httplib.error, socket.error, socket.timeout):
            errMsg = "unable to connect to Google"
            raise SqlmapConnectionException(errMsg)

        retVal = [urllib.unquote(match.group(1)) for match in re.finditer(GOOGLE_REGEX, page, re.I | re.S)]

        if not retVal and "detected unusual traffic" in page:
            warnMsg = "Google has detected 'unusual' traffic from "
            warnMsg += "used IP address disabling further searches"
            raise SqlmapGenericException(warnMsg)

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
                url += "&nextDDG=%s" % urlencode("/search?q=&num=100&hl=en&start=%d&sa=N" % ((gpage - 1) * 10), convall=True)
                url += "&sa=N&showIcons=false&filterIcons=none&js_enabled=1"
                regex = DISCONNECT_SEARCH_REGEX
            else:
                url = "https://duckduckgo.com/d.js?"
                url += "q=%s&p=%d&s=100" % (urlencode(dork, convall=True), gpage)
                regex = DUCKDUCKGO_REGEX

            if not conf.randomAgent:
                self.opener.addheaders = [_ for _ in self.opener.addheaders if _[0].lower() != HTTP_HEADER.USER_AGENT.lower()]
                self.opener.addheaders.append((HTTP_HEADER.USER_AGENT, DUMMY_SEARCH_USER_AGENT))

            self.opener.addheaders = [_ for _ in self.opener.addheaders if _[0].lower() != HTTP_HEADER.ACCEPT_ENCODING.lower()]
            self.opener.addheaders.append((HTTP_HEADER.ACCEPT_ENCODING, HTTP_ACCEPT_ENCODING_HEADER_VALUE))

            try:
                conn = self.opener.open(url)

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
