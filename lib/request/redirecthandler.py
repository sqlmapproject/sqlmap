#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import urllib2
import urlparse

from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.common import getHostHeader
from lib.core.common import getUnicode
from lib.core.common import logHTTPTraffic
from lib.core.common import readInput
from lib.core.enums import HTTPHEADER
from lib.core.enums import REDIRECTION
from lib.core.exception import sqlmapConnectionException
from lib.core.settings import MAX_SINGLE_URL_REDIRECTIONS
from lib.core.settings import MAX_TOTAL_REDIRECTIONS
from lib.core.threads import getCurrentThreadData
from lib.request.basic import decodePage

class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
    def _get_header_redirect(self, headers):
        retVal = None

        if headers:
            if "location" in headers:
                retVal = headers.getheaders("location")[0].split("?")[0]
            elif "uri" in headers:
                retVal = headers.getheaders("uri")[0].split("?")[0]

        return retVal

    def _ask_redirect_choice(self, redcode, redurl):
        if kb.redirectChoice is None and kb.originalPage:
            msg = "sqlmap got a %d redirect to " % redcode
            msg += "'%s'. What do you want to do? " % redurl
            msg += "\n[1] Follow the redirection (default)"
            msg += "\n[2] Stay on the original page"
            msg += "\n[3] Ignore"
            choice = readInput(msg, default="1")

            kb.redirectChoice = choice

    def _process_http_redirect(self, result, headers, code, content, msg, redurl):
        content = decodePage(content, headers.get(HTTPHEADER.CONTENT_ENCODING), headers.get(HTTPHEADER.CONTENT_TYPE))

        threadData = getCurrentThreadData()
        threadData.lastRedirectMsg = (threadData.lastRequestUID, content)

        responseMsg = "HTTP response "
        responseMsg += "[#%d] (%d %s):\n" % (threadData.lastRequestUID, code, getUnicode(msg))

        if headers:
            logHeaders = "\n".join("%s: %s" % (key.capitalize() if isinstance(key, basestring) else key, getUnicode(value)) for (key, value) in headers.items())
        else:
            logHeaders = ""

        logHTTPTraffic(threadData.lastRequestMsg, "%s%s" % (responseMsg, logHeaders))

        responseMsg += getUnicode(logHeaders)

        logger.log(7, responseMsg)

        if "set-cookie" in headers:
            kb.redirectSetCookie = headers["set-cookie"].split("; path")[0]

        result.redcode = code
        result.redurl = redurl

        return result

    def http_error_302(self, req, fp, code, msg, headers):
        content = None
        redurl = self._get_header_redirect(headers)

        if not urlparse.urlsplit(redurl).netloc:
            redurl = urlparse.urljoin(conf.url, redurl)

        self._infinite_loop_check(req)
        self._ask_redirect_choice(code, redurl)

        try:
            content = fp.read()
        except Exception, msg:
            dbgMsg = "there was a problem while retrieving "
            dbgMsg += "redirect response content (%s)" % msg
            logger.debug(dbgMsg)

        if kb.redirectChoice == REDIRECTION.FOLLOW or kb.originalPage is None:
            req.headers[HTTPHEADER.HOST] = getHostHeader(redurl)
            result = urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)
        else:
            result = fp

        return self._process_http_redirect(result, headers, code, content, msg, redurl)

    http_error_301 = http_error_303 = http_error_307 = http_error_302

    def _infinite_loop_check(self, req):
        if hasattr(req, 'redirect_dict') and (req.redirect_dict.get(req.get_full_url(), 0) >= MAX_SINGLE_URL_REDIRECTIONS or len(req.redirect_dict) >= MAX_TOTAL_REDIRECTIONS):
            errMsg = "infinite redirect loop detected (%s). " % ", ".join(item for item in req.redirect_dict.keys())
            errMsg += "please check all provided parameters and/or provide missing ones."
            raise sqlmapConnectionException, errMsg
