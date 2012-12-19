#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import gzip
import logging
import re
import StringIO
import struct
import zlib

from lib.core.common import extractErrorMessage
from lib.core.common import extractRegexResult
from lib.core.common import getUnicode
from lib.core.common import readInput
from lib.core.common import resetCookieJar
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import HTTPHEADER
from lib.core.enums import PLACE
from lib.core.exception import SqlmapCompressionException
from lib.core.htmlentities import htmlEntities
from lib.core.settings import DEFAULT_COOKIE_DELIMITER
from lib.core.settings import EVENTVALIDATION_REGEX
from lib.core.settings import MAX_CONNECTION_TOTAL_SIZE
from lib.core.settings import ML
from lib.core.settings import META_CHARSET_REGEX
from lib.core.settings import PARSE_HEADERS_LIMIT
from lib.core.settings import VIEWSTATE_REGEX
from lib.parse.headers import headersParser
from lib.parse.html import htmlParser
from thirdparty.chardet import detect

def forgeHeaders(items=None):
    """
    Prepare HTTP Cookie, HTTP User-Agent and HTTP Referer headers to use when performing
    the HTTP requests
    """

    items = items or {}

    for _ in items.keys():
        if items[_] is None:
            del items[_]

    headers = dict(conf.httpHeaders)
    headers.update(items or {})

    headers = dict(("-".join(_.capitalize() for _ in key.split('-')), value) for (key, value) in headers.items())

    if conf.cj:
        if HTTPHEADER.COOKIE in headers:
            for cookie in conf.cj:
                if ("%s=" % cookie.name) in headers[HTTPHEADER.COOKIE]:
                    if kb.mergeCookies is None:
                        message = "you provided a HTTP %s header value. " % HTTPHEADER.COOKIE
                        message += "The target url provided its own cookies within "
                        message += "the HTTP %s header which intersect with yours. " % HTTPHEADER.SET_COOKIE
                        message += "Do you want to merge them in futher requests? [Y/n] "
                        _ = readInput(message, default="Y")
                        kb.mergeCookies = not _ or _[0] in ("y", "Y")

                    if kb.mergeCookies:
                        _ = lambda x: re.sub("(?i)%s=[^%s]+" % (cookie.name, DEFAULT_COOKIE_DELIMITER), "%s=%s" % (cookie.name, cookie.value), x)
                        headers[HTTPHEADER.COOKIE] = _(headers[HTTPHEADER.COOKIE])

                        if PLACE.COOKIE in conf.parameters:
                            conf.parameters[PLACE.COOKIE] = _(conf.parameters[PLACE.COOKIE])

                        conf.httpHeaders = [(item[0], item[1] if item[0] != HTTPHEADER.COOKIE else _(item[1])) for item in conf.httpHeaders]

                elif not kb.testMode:
                    headers[HTTPHEADER.COOKIE] += "%s %s=%s" % (DEFAULT_COOKIE_DELIMITER, cookie.name, cookie.value)

        if kb.testMode:
            resetCookieJar(conf.cj)

    if kb.redirectSetCookie and not conf.dropSetCookie:
        if HTTPHEADER.COOKIE in headers:
            headers[HTTPHEADER.COOKIE] += "%s %s" % (DEFAULT_COOKIE_DELIMITER, kb.redirectSetCookie)
        else:
            headers[HTTPHEADER.COOKIE] = kb.redirectSetCookie

    return headers

def parseResponse(page, headers):
    """
    @param page: the page to parse to feed the knowledge base htmlFp
    (back-end DBMS fingerprint based upon DBMS error messages return
    through the web application) list and absFilePaths (absolute file
    paths) set.
    """

    if headers:
        headersParser(headers)

    if page:
        htmlParser(page)

def checkCharEncoding(encoding, warn=True):
    if encoding:
        encoding = encoding.lower()
    else:
        return encoding

    # http://www.destructor.de/charsets/index.htm
    translate = { "windows-874": "iso-8859-11", "en_us": "utf8", "macintosh": "iso-8859-1", "euc_tw": "big5_tw", "th": "tis-620", "unicode": "utf8",  "utc8": "utf8", "ebcdic": "ebcdic-cp-be"}

    for delimiter in (';', ',', '('):
        if delimiter in encoding:
            encoding = encoding[:encoding.find(delimiter)].strip()

    # popular typos/errors
    if "8858" in encoding:
        encoding = encoding.replace("8858", "8859") # iso-8858 -> iso-8859
    elif "8559" in encoding:
        encoding = encoding.replace("8559", "8859") # iso-8559 -> iso-8859
    elif "5889" in encoding:
        encoding = encoding.replace("5889", "8859") # iso-5889 -> iso-8859
    elif "5589" in encoding:
        encoding = encoding.replace("5589", "8859") # iso-5589 -> iso-8859
    elif "2313" in encoding:
        encoding = encoding.replace("2313", "2312") # gb2313 -> gb2312
    elif "x-euc" in encoding:
        encoding = encoding.replace("x-euc", "euc") # x-euc-kr -> euc-kr

    # name adjustment for compatibility
    if encoding.startswith("8859"):
        encoding = "iso-%s" % encoding
    elif encoding.startswith("cp-"):
        encoding = "cp%s" % encoding[3:]
    elif encoding.startswith("euc-"):
        encoding = "euc_%s" % encoding[4:]
    elif encoding.startswith("windows") and not encoding.startswith("windows-"):
        encoding = "windows-%s" % encoding[7:]
    elif encoding.find("iso-88") > 0:
        encoding = encoding[encoding.find("iso-88"):]
    elif encoding.startswith("is0-"):
        encoding = "iso%s" % encoding[4:]
    elif encoding.find("ascii") > 0:
        encoding = "ascii"
    elif encoding.find("utf8") > 0:
        encoding = "utf8"

    # http://philip.html5.org/data/charsets-2.html
    if encoding in translate:
        encoding = translate[encoding]
    elif encoding in ("null", "{charset}", "*"):
        return None

    # http://www.iana.org/assignments/character-sets
    # http://docs.python.org/library/codecs.html
    try:
        codecs.lookup(encoding)
    except LookupError:
        if warn:
            warnMsg = "unknown web page charset '%s'. " % encoding
            warnMsg += "Please report by e-mail to %s." % ML
            singleTimeLogMessage(warnMsg, logging.WARN, encoding)
        encoding = None

    return encoding

def getHeuristicCharEncoding(page):
    """
    Returns page encoding charset detected by usage of heuristics
    Reference: http://chardet.feedparser.org/docs/
    """
    retVal = detect(page)["encoding"]

    infoMsg = "heuristics detected web page charset '%s'" % retVal
    singleTimeLogMessage(infoMsg, logging.INFO, retVal)

    return retVal

def decodePage(page, contentEncoding, contentType):
    """
    Decode compressed/charset HTTP response
    """

    if not page or (conf.nullConnection and len(page) < 2):
        return getUnicode(page)

    if isinstance(contentEncoding, basestring) and contentEncoding.lower() in ("gzip", "x-gzip", "deflate"):
        if not kb.pageCompress:
            return None

        try:
            if contentEncoding.lower() == "deflate":
                data = StringIO.StringIO(zlib.decompress(page, -15))  # Reference: http://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
            else:
                data = gzip.GzipFile("", "rb", 9, StringIO.StringIO(page))
                size = struct.unpack("<l", page[-4:])[0]  # Reference: http://pydoc.org/get.cgi/usr/local/lib/python2.5/gzip.py
                if size > MAX_CONNECTION_TOTAL_SIZE:
                    raise Exception, "size too large"

            page = data.read()
        except Exception, msg:
            errMsg = "detected invalid data for declared content "
            errMsg += "encoding '%s' ('%s')" % (contentEncoding, msg)
            singleTimeLogMessage(errMsg, logging.ERROR)

            warnMsg = "turning off page compression"
            singleTimeWarnMessage(warnMsg)

            kb.pageCompress = False
            raise SqlmapCompressionException

    if not conf.charset:
        httpCharset, metaCharset = None, None

        # http://stackoverflow.com/questions/1020892/python-urllib2-read-to-unicode
        if contentType and (contentType.find("charset=") != -1):
            httpCharset = checkCharEncoding(contentType.split("charset=")[-1])

        metaCharset = checkCharEncoding(extractRegexResult(META_CHARSET_REGEX, page))

        if (any((httpCharset, metaCharset)) and not all((httpCharset, metaCharset)))\
            or (httpCharset == metaCharset and all((httpCharset, metaCharset))):
            kb.pageEncoding = httpCharset or metaCharset
            debugMsg = "declared web page charset '%s'" % kb.pageEncoding
            singleTimeLogMessage(debugMsg, logging.DEBUG, debugMsg)
        else:
            kb.pageEncoding = None
    else:
        kb.pageEncoding = conf.charset

    # can't do for all responses because we need to support binary files too
    if contentType and not isinstance(page, unicode) and any(map(lambda _: _ in contentType.lower(), ("text/txt", "text/raw", "text/html", "text/xml"))):
        # e.g. &#195;&#235;&#224;&#226;&#224;
        if "&#" in page:
            page = re.sub('&#(\d{1,3});', lambda _: chr(int(_.group(1))) if int(_.group(1)) < 256 else _.group(0), page)

        # e.g. &amp;
        page = re.sub('&([^;]+);', lambda _: chr(htmlEntities[_.group(1)]) if htmlEntities.get(_.group(1), 256) < 256 else _.group(0), page)

        kb.pageEncoding = kb.pageEncoding or checkCharEncoding(getHeuristicCharEncoding(page))
        page = getUnicode(page, kb.pageEncoding)

        # e.g. &#8217;&#8230;&#8482;
        if "&#" in page:
            page = re.sub('&#(\d+);', lambda _: unichr(int(_.group(1))), page)

        # e.g. &zeta;
        page = re.sub('&([^;]+);', lambda _: unichr(htmlEntities[_.group(1)]) if htmlEntities.get(_.group(1), 0) > 255 else _.group(0), page)

    return page

def processResponse(page, responseHeaders):
    kb.processResponseCounter += 1

    if not kb.dumpTable:
        parseResponse(page, responseHeaders if kb.processResponseCounter < PARSE_HEADERS_LIMIT else None)

    if conf.parseErrors:
        msg = extractErrorMessage(page)

        if msg:
            logger.info("parsed error message: '%s'" % msg)

    if kb.originalPage is None:
        for regex in (EVENTVALIDATION_REGEX, VIEWSTATE_REGEX):
            match = re.search(regex, page)
            if match and PLACE.POST in conf.parameters:
                name, value = match.groups()
                if PLACE.POST in conf.paramDict and name in conf.paramDict[PLACE.POST]:
                    if conf.paramDict[PLACE.POST][name] in page:
                        continue
                    conf.paramDict[PLACE.POST][name] = value
                conf.parameters[PLACE.POST] = re.sub("(?i)(%s=)[^&]+" % name, r"\g<1>%s" % value, conf.parameters[PLACE.POST])
