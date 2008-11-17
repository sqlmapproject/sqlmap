#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

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



import re

from xml.sax import parse
from xml.sax.handler import ContentHandler

from lib.core.common import checkFile
from lib.core.common import sanitizeStr
from lib.core.data import kb
from lib.core.data import paths
from lib.parse.banner import BannerHandler

def headersParser(headers):
    """
    This function calls a class that parses the input HTTP headers to
    fingerprint the back-end database management system operating system
    and web application technology
    """

    topHeaders = {
                   "cookie",
                   "microsoftsharepointteamservices",
                   "server",
                   "servlet-engine",
                   "www-authenticate",
                   "x-aspnet-version",
                   "x-powered-by",
                 }

    for header in headers:
        if header in topHeaders:
            pass
