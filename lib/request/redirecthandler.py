#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import types
import urllib2
import urlparse

from StringIO import StringIO

from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.common import getHostHeader
from lib.core.common import getUnicode
from lib.core.common import logHTTPTraffic
from lib.core.common import readInput
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import REDIRECTION
from lib.core.exception import SqlmapConnectionException
from lib.core.settings import DEFAULT_COOKIE_DELIMITER
from lib.core.settings import MAX_CONNECTION_CHUNK_SIZE
from lib.core.settings import MAX_CONNECTION_TOTAL_SIZE
from lib.core.settings import MAX_SINGLE_URL_REDIRECTIONS
from lib.core.settings import MAX_TOTAL_REDIRECTIONS
from lib.core.threads import getCurrentThreadData
from lib.request.basic import decodePage
from lib.request.basic import parseResponse

class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
    def _get_header_redirect(self, headers):
        retVal = None

        if headers:
            if "location" in headers:
                retVal = headers.getheaders("location")[0]
            elif "uri" in headers:
                retVal = headers.getheaders("uri")[0]

        return retVal

    def _ask_redirect_choice(self, redcode, redurl, method):
        with kb.locks.redirect:
            if kb.redirectChoice is None:
                msg = "sqlmap got a %d redirect to " % redcode
                msg += "'%s'. Do you want to follow? [Y/n] " % redurl
                choice = readInput(msg, default="Y")

                kb.redirectChoice = choice.upper()

            if kb.redirectChoice == REDIRECTION.YES and method == HTTPMETHOD.POST and kb.resendPostOnRedirect is None:
                msg = "redirect is a result of a "
                msg += "POST request. Do you want to "
                msg += "resend original POST data to a new "
                msg += "location? [%s] " % ("Y/n" if not kb.originalPage else "y/N")
                choice = readInput(msg, default=("Y" if not kb.originalPage else "N"))

                kb.resendPostOnRedirect = choice.upper() == 'Y'

            if kb.resendPostOnRedirect:
                self.redirect_request = self._redirect_request

    def _redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl = newurl.replace(' ', '%20')
        return urllib2.Request(newurl, data=req.data, headers=req.headers, origin_req_host=req.get_origin_req_host())

    def http_error_302(self, req, fp, code, msg, headers):
        content = None
        redurl = self._get_header_redirect(headers) if not conf.ignoreRedirects else None

        try:
            content = fp.read(MAX_CONNECTION_TOTAL_SIZE)
        except Exception, msg:
            dbgMsg = "there was a problem while retrieving "
            dbgMsg += "redirect response content (%s)" % msg
            logger.debug(dbgMsg)
        finally:
            if content:
                try:  # try to write it back to the read buffer so we could reuse it in further steps
                    fp.fp._rbuf.truncate(0)
                    fp.fp._rbuf.write(content)
                except:
                    pass

        content = decodePage(content, headers.get(HTTP_HEADER.CONTENT_ENCODING), headers.get(HTTP_HEADER.CONTENT_TYPE))

        threadData = getCurrentThreadData()
        threadData.lastRedirectMsg = (threadData.lastRequestUID, content)

        redirectMsg = "HTTP redirect "
        redirectMsg += "[#%d] (%d %s):\n" % (threadData.lastRequestUID, code, getUnicode(msg))

        if headers:
            logHeaders = "\n".join("%s: %s" % (getUnicode(key.capitalize() if isinstance(key, basestring) else key), getUnicode(value)) for (key, value) in headers.items())
        else:
            logHeaders = ""

        redirectMsg += logHeaders
        if content:
            redirectMsg += "\n\n%s" % getUnicode(content[:MAX_CONNECTION_CHUNK_SIZE])

        logHTTPTraffic(threadData.lastRequestMsg, redirectMsg)
        logger.log(CUSTOM_LOGGING.TRAFFIC_IN, redirectMsg)

        if redurl:
            try:
                if not urlparse.urlsplit(redurl).netloc:
                    redurl = urlparse.urljoin(req.get_full_url(), redurl)

                self._infinite_loop_check(req)
                self._ask_redirect_choice(code, redurl, req.get_method())
            except ValueError:
                redurl = None
                result = fp

        if redurl and kb.redirectChoice == REDIRECTION.YES:
            parseResponse(content, headers)

            req.headers[HTTP_HEADER.HOST] = getHostHeader(redurl)
            if headers and HTTP_HEADER.SET_COOKIE in headers:
                req.headers[HTTP_HEADER.COOKIE] = headers[HTTP_HEADER.SET_COOKIE].split(conf.cookieDel or DEFAULT_COOKIE_DELIMITER)[0]
            try:
                result = urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)
            except urllib2.HTTPError, e:
                result = e

                # Dirty hack for http://bugs.python.org/issue15701
                try:
                    result.info()
                except AttributeError:
                    def _(self):
                        return getattr(self, "hdrs") or {}
                    result.info = types.MethodType(_, result)

                if not hasattr(result, "read"):
                    def _(self, length=None):
                        return e.msg
                    result.read = types.MethodType(_, result)

                if not getattr(result, "url", None):
                    result.url = redurl

                if not getattr(result, "code", None):
                    result.code = 999
            except:
                redurl = None
                result = fp
                fp.read = StringIO("").read
        else:
            result = fp

        threadData.lastRedirectURL = (threadData.lastRequestUID, redurl)

        result.redcode = code
        result.redurl = redurl
        return result

    http_error_301 = http_error_303 = http_error_307 = http_error_302

    def _infinite_loop_check(self, req):
        if hasattr(req, 'redirect_dict') and (req.redirect_dict.get(req.get_full_url(), 0) >= MAX_SINGLE_URL_REDIRECTIONS or len(req.redirect_dict) >= MAX_TOTAL_REDIRECTIONS):
            errMsg = "infinite redirect loop detected (%s). " % ", ".join(item for item in req.redirect_dict.keys())
            errMsg += "Please check all provided parameters and/or provide missing ones"
            raise SqlmapConnectionException(errMsg)
