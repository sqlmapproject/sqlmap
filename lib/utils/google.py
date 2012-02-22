#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import cookielib
import httplib
import re
import socket
import urllib2

from lib.core.common import getUnicode
from lib.core.common import readInput
from lib.core.convert import urldecode
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapGenericException
from lib.core.settings import GOOGLE_REGEX
from lib.core.settings import UNICODE_ENCODING
from lib.core.settings import URI_INJECTABLE_REGEX
from lib.request.basic import decodePage

class Google:
    """
    This class defines methods used to perform Google dorking (command
    line option '-g <google dork>'
    """

    def __init__(self, handlers):
        self._matches = []
        self._cj = cookielib.LWPCookieJar()

        handlers.append(urllib2.HTTPCookieProcessor(self._cj))

        self.opener = urllib2.build_opener(*handlers)
        self.opener.addheaders = conf.httpHeaders

    def _parsePage(self, page):
        """
        Parse Google dork search results page to get the list of
        HTTP addresses
        """

        retVal = re.findall(GOOGLE_REGEX, page, re.I | re.S)

        return retVal

    def getTargetUrls(self):
        """
        This method returns the list of hosts with parameters out of
        your Google dork search results
        """

        for _ in self._matches:
            _ = urldecode(_)
            if re.search(r"(.*?)\?(.+)", _):
                kb.targetUrls.add((_, None, None, None))
            elif re.search(URI_INJECTABLE_REGEX, _, re.I):
                if kb.scanOnlyGoogleGETs is None:
                    message = "do you want to scan only results containing GET parameters? [Y/n] "
                    test = readInput(message, default="Y")
                    kb.scanOnlyGoogleGETs = test.lower() != 'n'
                if not kb.scanOnlyGoogleGETs:
                    kb.targetUrls.add((_, None, None, None))

    def getCookie(self):
        """
        This method is the first to be called when initializing a
        Google dorking object through this library. It is used to
        retrieve the Google session cookie needed to perform the
        further search
        """

        try:
            conn = self.opener.open("http://www.google.com/ncr")
            _ = conn.info()
        except urllib2.HTTPError, e:
            _ = e.info()
        except urllib2.URLError:
            errMsg = "unable to connect to Google"
            raise sqlmapConnectionException, errMsg

    def search(self, googleDork):
        """
        This method performs the effective search on Google providing
        the google dork and the Google session cookie
        """

        gpage = conf.googlePage if conf.googlePage > 1 else 1
        logger.info("using Google result page #%d" % gpage)

        if not googleDork:
            return None

        url = "http://www.google.com/search?"
        url += "q=%s&" % urlencode(googleDork, convall=True)
        url += "num=100&hl=en&complete=0&safe=off&filter=0&btnG=Search"
        url += "&start=%d" % ((gpage-1) * 100)

        try:
            conn = self.opener.open(url)

            requestMsg = "HTTP request:\nGET %s" % url
            requestMsg += " %s" % httplib.HTTPConnection._http_vsn_str
            logger.log(8, requestMsg)

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

            logger.log(7, responseMsg)
        except urllib2.HTTPError, e:
            try:
                page = e.read()
            except socket.timeout:
                warnMsg = "connection timed out while trying "
                warnMsg += "to get error page information (%d)" % e.code
                logger.critical(warnMsg)
                return None
        except (urllib2.URLError, socket.error, socket.timeout):
            errMsg = "unable to connect to Google"
            raise sqlmapConnectionException, errMsg

        self._matches = self._parsePage(page)

        if not self._matches and "detected unusual traffic" in page:
            warnMsg = "Google has detected 'unusual' traffic from "
            warnMsg += "this computer disabling further searches"
            raise sqlmapGenericException, warnMsg

        return self._matches
