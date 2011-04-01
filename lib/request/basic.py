#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import codecs
import gzip
import os
import re
import StringIO
import zlib

from lib.core.common import extractErrorMessage
from lib.core.common import extractRegexResult
from lib.core.common import getCompiledRegex
from lib.core.common import getUnicode
from lib.core.common import isWindowsDriveLetterPath
from lib.core.common import posixToNtSlashes
from lib.core.common import sanitizeAsciiString
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.settings import ML
from lib.core.settings import META_CHARSET_REGEX
from lib.core.settings import DEFAULT_PAGE_ENCODING
from lib.core.settings import UNICODE_ENCODING
from lib.parse.headers import headersParser
from lib.parse.html import htmlParser

def forgeHeaders(cookie, ua, referer):
    """
    Prepare HTTP Cookie, HTTP User-Agent and HTTP Referer headers to use when performing
    the HTTP requests
    """

    headers = {}

    for header, value in conf.httpHeaders:
        if cookie and header == "Cookie":
            headers[header] = cookie
        elif ua and header == "User-Agent":
            headers[header] = ua
        elif referer and header == "Referer":
            headers[header] = referer
        else:
            headers[header] = value

    if kb.redirectSetCookie:
        if "Cookie" in headers:
            headers["Cookie"] = "%s; %s" % (headers["Cookie"], kb.redirectSetCookie)
        else:
            headers["Cookie"] = kb.redirectSetCookie

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

        # Detect injectable page absolute system path
        # NOTE: this regular expression works if the remote web
        # application is written in PHP and debug/error messages are
        # enabled
        for regex in ( r" in <b>(?P<result>.*?)</b> on line",  r"(?:>|\s)(?P<result>[A-Za-z]:[\\/][\w.\\/]*)", r"(?:>|\s)(?P<result>/\w[/\w.]+)" ):
            regObj = getCompiledRegex(regex)

            for match in regObj.finditer(page):
                absFilePath = match.group("result").strip()
                page = page.replace(absFilePath, "")

                if isWindowsDriveLetterPath(absFilePath):
                    absFilePath = posixToNtSlashes(absFilePath)

                if absFilePath not in kb.absFilePaths:
                    kb.absFilePaths.add(absFilePath)

def checkCharEncoding(encoding):
    if encoding:
        encoding = encoding.lower()
    else:
        return encoding

    # http://www.destructor.de/charsets/index.htm
    translate = { 'windows-874': 'iso-8859-11', 'en_us': 'utf8', 'macintosh': 'iso-8859-1' }

    for delimiter in (';', ','):
        if delimiter in encoding:
            encoding = encoding[:encoding.find(delimiter)]

    # popular typos/errors
    if '8858' in encoding:
        encoding = encoding.replace('8858', '8859')
    if encoding.startswith('8859'):
        encoding = 'iso-%s' % encoding

    # http://philip.html5.org/data/charsets-2.html
    if encoding in translate:
        encoding = translate[encoding]
    elif encoding.startswith('cp-'):
        encoding = 'cp%s' % encoding[3:]
    elif encoding.startswith('windows') and not encoding.startswith('windows-'):
        encoding = 'windows-%s' % encoding[7:]
    elif encoding == 'null':
        return None

    # http://www.iana.org/assignments/character-sets
    try:
        codecs.lookup(encoding)
    except LookupError:
        warnMsg  = "unknown charset '%s'. " % encoding
        warnMsg += "Please report by e-mail to %s." % ML
        logger.warn(warnMsg)
        encoding = UNICODE_ENCODING

    return encoding

def decodePage(page, contentEncoding, contentType):
    """
    Decode compressed/charset HTTP response
    """

    if not page or (conf.nullConnection and len(page) < 2):
        return getUnicode(page)

    if isinstance(contentEncoding, basestring) and contentEncoding.lower() in ('gzip', 'x-gzip', 'deflate'):
        if contentEncoding == 'deflate':
            # http://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
            data = StringIO.StringIO(zlib.decompress(page, -15))
        else:
            data = gzip.GzipFile('', 'rb', 9, StringIO.StringIO(page))

        page = data.read()

    charset = None

    # http://stackoverflow.com/questions/1020892/python-urllib2-read-to-unicode
    if contentType and (contentType.find('charset=') != -1):
        charset = contentType.split('charset=')[-1]
    elif extractRegexResult(META_CHARSET_REGEX, page, re.DOTALL | re.IGNORECASE):
        charset = extractRegexResult(META_CHARSET_REGEX, page, re.DOTALL | re.IGNORECASE)

    charset = checkCharEncoding(charset)
    kb.pageEncoding = charset or DEFAULT_PAGE_ENCODING

    if contentType and any(map(lambda x: x in contentType.lower(), ('text/txt', 'text/raw', 'text/html', 'text/xml'))):
        # can't do for all responses because we need to support binary files too
        page = getUnicode(page, kb.pageEncoding)

    return page

def processResponse(page, responseHeaders):
    parseResponse(page, responseHeaders)

    if conf.parseErrors:
        msg = extractErrorMessage(page)

        if msg:
            logger.info("parsed error message: '%s'" % msg) 

    return page
