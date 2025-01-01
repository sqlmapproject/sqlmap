#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import io
import re
import time
import types

from lib.core.common import getHostHeader
from lib.core.common import getSafeExString
from lib.core.common import logHTTPTraffic
from lib.core.common import readInput
from lib.core.convert import getBytes
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import REDIRECTION
from lib.core.exception import SqlmapConnectionException
from lib.core.settings import DEFAULT_COOKIE_DELIMITER
from lib.core.settings import MAX_CONNECTION_READ_SIZE
from lib.core.settings import MAX_CONNECTION_TOTAL_SIZE
from lib.core.settings import MAX_SINGLE_URL_REDIRECTIONS
from lib.core.settings import MAX_TOTAL_REDIRECTIONS
from lib.core.threads import getCurrentThreadData
from lib.request.basic import decodePage
from lib.request.basic import parseResponse
from thirdparty import six
from thirdparty.six.moves import urllib as _urllib

class SmartRedirectHandler(_urllib.request.HTTPRedirectHandler):
    def _get_header_redirect(self, headers):
        retVal = None

        if headers:
            if HTTP_HEADER.LOCATION in headers:
                retVal = headers[HTTP_HEADER.LOCATION]
            elif HTTP_HEADER.URI in headers:
                retVal = headers[HTTP_HEADER.URI]

        return retVal

    def _ask_redirect_choice(self, redcode, redurl, method):
        with kb.locks.redirect:
            if kb.choices.redirect is None:
                msg = "got a %d redirect to " % redcode
                msg += "'%s'. Do you want to follow? [Y/n] " % redurl

                kb.choices.redirect = REDIRECTION.YES if readInput(msg, default='Y', boolean=True) else REDIRECTION.NO

            if kb.choices.redirect == REDIRECTION.YES and method == HTTPMETHOD.POST and kb.resendPostOnRedirect is None:
                msg = "redirect is a result of a "
                msg += "POST request. Do you want to "
                msg += "resend original POST data to a new "
                msg += "location? [%s] " % ("Y/n" if not kb.originalPage else "y/N")

                kb.resendPostOnRedirect = readInput(msg, default=('Y' if not kb.originalPage else 'N'), boolean=True)

            if kb.resendPostOnRedirect:
                self.redirect_request = self._redirect_request

    def _redirect_request(self, req, fp, code, msg, headers, newurl):
        return _urllib.request.Request(newurl.replace(' ', '%20'), data=req.data, headers=req.headers, origin_req_host=req.get_origin_req_host() if hasattr(req, "get_origin_req_host") else req.origin_req_host)

    def http_error_302(self, req, fp, code, msg, headers):
        start = time.time()
        content = None
        forceRedirect = False
        redurl = self._get_header_redirect(headers) if not conf.ignoreRedirects else None

        try:
            content = fp.read(MAX_CONNECTION_TOTAL_SIZE)
        except:  # e.g. IncompleteRead
            content = b""
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
        redirectMsg += "[#%d] (%d %s):\r\n" % (threadData.lastRequestUID, code, getUnicode(msg))

        if headers:
            logHeaders = "\r\n".join("%s: %s" % (getUnicode(key.capitalize() if hasattr(key, "capitalize") else key), getUnicode(value)) for (key, value) in headers.items())
        else:
            logHeaders = ""

        redirectMsg += logHeaders
        if content:
            redirectMsg += "\r\n\r\n%s" % getUnicode(content[:MAX_CONNECTION_READ_SIZE])

        logHTTPTraffic(threadData.lastRequestMsg, redirectMsg, start, time.time())
        logger.log(CUSTOM_LOGGING.TRAFFIC_IN, redirectMsg)

        if redurl:
            try:
                if not _urllib.parse.urlsplit(redurl).netloc:
                    redurl = _urllib.parse.urljoin(req.get_full_url(), redurl)

                self._infinite_loop_check(req)
                if conf.scope:
                    if not re.search(conf.scope, redurl, re.I):
                        redurl = None
                    else:
                        forceRedirect = True
                else:
                    self._ask_redirect_choice(code, redurl, req.get_method())
            except ValueError:
                redurl = None
                result = fp

        if redurl and (kb.choices.redirect == REDIRECTION.YES or forceRedirect):
            parseResponse(content, headers)

            req.headers[HTTP_HEADER.HOST] = getHostHeader(redurl)
            if headers and HTTP_HEADER.SET_COOKIE in headers:
                cookies = dict()
                delimiter = conf.cookieDel or DEFAULT_COOKIE_DELIMITER
                last = None

                for part in getUnicode(req.headers.get(HTTP_HEADER.COOKIE, "")).split(delimiter) + ([headers[HTTP_HEADER.SET_COOKIE]] if HTTP_HEADER.SET_COOKIE in headers else []):
                    if '=' in part:
                        part = part.strip()
                        key, value = part.split('=', 1)
                        cookies[key] = value
                        last = key
                    elif last:
                        cookies[last] += "%s%s" % (delimiter, part)

                req.headers[HTTP_HEADER.COOKIE] = delimiter.join("%s=%s" % (key, cookies[key]) for key in cookies)

            try:
                result = _urllib.request.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)
            except _urllib.error.HTTPError as ex:
                result = ex

                # Dirty hack for https://github.com/sqlmapproject/sqlmap/issues/4046
                try:
                    hasattr(result, "read")
                except KeyError:
                    class _(object):
                        pass
                    result = _()

                # Dirty hack for http://bugs.python.org/issue15701
                try:
                    result.info()
                except AttributeError:
                    def _(self):
                        return getattr(self, "hdrs", {})

                    result.info = types.MethodType(_, result)

                if not hasattr(result, "read"):
                    def _(self, length=None):
                        try:
                            retVal = getSafeExString(ex)        # Note: pyflakes mistakenly marks 'ex' as undefined (NOTE: tested in both Python2 and Python3)
                        except:
                            retVal = ""
                        return getBytes(retVal)

                    result.read = types.MethodType(_, result)

                if not getattr(result, "url", None):
                    result.url = redurl

                if not getattr(result, "code", None):
                    result.code = 999
            except:
                redurl = None
                result = fp
                fp.read = io.BytesIO(b"").read
        else:
            result = fp

        threadData.lastRedirectURL = (threadData.lastRequestUID, redurl)

        result.redcode = code
        result.redurl = getUnicode(redurl) if six.PY3 else redurl
        return result

    http_error_301 = http_error_303 = http_error_307 = http_error_302

    def _infinite_loop_check(self, req):
        if hasattr(req, 'redirect_dict') and (req.redirect_dict.get(req.get_full_url(), 0) >= MAX_SINGLE_URL_REDIRECTIONS or len(req.redirect_dict) >= MAX_TOTAL_REDIRECTIONS):
            errMsg = "infinite redirect loop detected (%s). " % ", ".join(item for item in req.redirect_dict.keys())
            errMsg += "Please check all provided parameters and/or provide missing ones"
            raise SqlmapConnectionException(errMsg)
