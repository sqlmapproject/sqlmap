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

from lib.core.common import getCompiledRegex
from lib.core.common import getUnicode
from lib.core.common import isWindowsDriveLetterPath
from lib.core.common import posixToNtSlashes
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.parse.headers import headersParser
from lib.parse.html import htmlParser

def forgeHeaders(cookie, ua):
    """
    Prepare HTTP Cookie and HTTP User-Agent headers to use when performing
    the HTTP requests
    """

    headers = {}

    for header, value in conf.httpHeaders:
        if cookie and header == "Cookie":
            headers[header] = cookie
        elif ua and header == "User-Agent":
            headers[header] = ua
        else:
            headers[header] = value

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
        # NOTE: this regular expression works if the remote web application
        # is written in PHP and debug/error messages are enabled.

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
    translate = { 'windows-874': 'iso-8859-11', 'en_us': 'utf8' }

    for delimiter in (';', ','):
        if delimiter in encoding:
            encoding = encoding[:encoding.find(delimiter)]

    # http://philip.html5.org/data/charsets-2.html
    if encoding in translate:
        encoding = translate[encoding]
    elif encoding.startswith('cp-'):
        encoding = 'cp%s' % encoding[3:]
    elif encoding.startswith('windows') and not encoding.startswith('windows-'):
        encoding = 'windows-%s' % encoding[7:]
    elif encoding == 'null':
        return None

    try:
        codecs.lookup(encoding)
    except LookupError:
        warnMsg  = "unknown charset '%s'. " % encoding
        warnMsg += "Please report by e-mail to sqlmap-users@lists.sourceforge.net."
        logger.warn(warnMsg)
        encoding = conf.dataEncoding

    return encoding

def decodePage(page, contentEncoding, contentType):
    """
    Decode compressed/charset HTTP response
    """

    if isinstance(contentEncoding, basestring) and contentEncoding.lower() in ('gzip', 'x-gzip', 'deflate'):
        if contentEncoding == 'deflate':
            # http://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
            data = StringIO.StringIO(zlib.decompress(page, -15))
        else:
            data = gzip.GzipFile('', 'rb', 9, StringIO.StringIO(page))

        page = data.read()

    # http://stackoverflow.com/questions/1020892/python-urllib2-read-to-unicode
    if contentType and (contentType.find('charset=') != -1):
        charset = checkCharEncoding(contentType.split('charset=')[-1])

        if charset:
            page = getUnicode(page, charset)

    return page
