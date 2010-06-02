#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

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

import gzip
import os
import re
import StringIO
import zlib

from lib.core.common import getCompiledRegex
from lib.core.common import isWindowsDriveLetterPath
from lib.core.common import posixToNtSlashes
from lib.core.common import urlEncodeCookieValues
from lib.core.data import conf
from lib.core.data import kb
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
            if conf.cookieUrlencode:
                cookie = urlEncodeCookieValues(cookie)

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
                    

def decodePage(page, encoding):
    """
    Decode gzip/deflate HTTP response
    """

    if isinstance(encoding, basestring) and encoding.lower() in ('gzip', 'x-gzip', 'deflate'):
        if encoding == 'deflate':
            # http://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
            data = StringIO.StringIO(zlib.decompress(page, -15))
        else:
            data = gzip.GzipFile('', 'rb', 9, StringIO.StringIO(page))

        page = data.read()

    return page
