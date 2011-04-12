#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import urllib2

from lib.core.data import conf
from lib.core.data import logger
from lib.core.common import getUnicode
from lib.core.enums import HTTPHEADER
from lib.core.exception import sqlmapConnectionException
from lib.core.threads import getCurrentThreadData
from lib.request.basic import decodePage

class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
    # maximum number of redirections to any single URL
    # this is needed because of the state that cookies introduce
    max_repeats = 4

    # maximum total number of redirections (regardless of URL) before
    # assuming we're in a loop
    max_redirections = 10

    def common_http_redirect(self, result, headers, code, content, msg):
        content = decodePage(content, headers.get(HTTPHEADER.CONTENT_ENCODING), headers.get(HTTPHEADER.CONTENT_TYPE))

        threadData = getCurrentThreadData()
        threadData.lastRedirectMsg = (threadData.lastRequestUID, content)

        responseMsg = "HTTP response "
        responseMsg += "[#%d] (%d %s):\n" % (threadData.lastRequestUID, code, getUnicode(msg))

        if headers:
            logHeaders = "\n".join(["%s: %s" % (key.capitalize() if isinstance(key, basestring) else key, getUnicode(value)) for (key, value) in headers.items()])
        else:
            logHeaders = ""

        if conf.verbose <= 5:
            responseMsg += getUnicode(logHeaders)
        elif conf.verbose > 5:
            responseMsg += "%s\n\n%s\n" % (logHeaders, content)

        logger.log(7, responseMsg)

        if "location" in headers:
            result.redurl = headers.getheaders("location")[0].split("?")[0]
        elif "uri" in headers:
            result.redurl = headers.getheaders("uri")[0].split("?")[0]

        if "set-cookie" in headers:
            result.setcookie = headers["set-cookie"].split("; path")[0]

        if result:
            result.redcode = code

        return result

    def http_error_301(self, req, fp, code, msg, headers):
        self.infinite_loop_check(req)

        content = None
        try:
            content = fp.read()
        except Exception, msg:
            dbgMsg  = "there was a problem while retrieving "
            dbgMsg += "redirect response content (%s)" % msg
            logger.debug(dbgMsg)

        result = urllib2.HTTPRedirectHandler.http_error_301(self, req, fp, code, msg, headers)
        return self.common_http_redirect(result, headers, code, content, msg)

    def http_error_302(self, req, fp, code, msg, headers):
        self.infinite_loop_check(req)

        content = None
        try:
            content = fp.read()
        except Exception, msg:
            dbgMsg  = "there was a problem while retrieving "
            dbgMsg += "redirect response content (%s)" % msg
            logger.debug(dbgMsg)

        result = urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)
        return self.common_http_redirect(result, headers, code, content, msg)

    def infinite_loop_check(self, req):
        if hasattr(req, 'redirect_dict') and (req.redirect_dict.get(req.get_full_url(), 0) >= self.max_repeats or len(req.redirect_dict) >= self.max_redirections):
            errMsg  = "infinite redirect loop detected (%s). " % ", ".join(item for item in req.redirect_dict.keys())
            errMsg += "please check all provided parameters and/or provide missing ones."
            raise sqlmapConnectionException, errMsg
