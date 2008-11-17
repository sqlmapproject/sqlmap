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


class HeadersHandler(ContentHandler):
    """
    This class defines methods to parse and extract information from
    the given HTTP header based upon the data in XML file
    """

    def __init__(self, header):
        self.__header   = sanitizeStr(header)

        self.__regexp      = None
        self.__match       = None
        self.__techVersion = None


    def __feedInfo(self, key, value):
        value = sanitizeStr(value)

        if value in ( None, "None" ):
            return

        if key == "techVersion":
            kb.headersFp[key] = value
        else:
            if key not in kb.headersFp.keys():
                kb.headersFp[key] = set()

            kb.headersFp[key].add(value)


    def startElement(self, name, attrs):
        if name == "regexp":
            self.__regexp = sanitizeStr(attrs.get("value"))
            self.__match  = re.search(self.__regexp, self.__header, re.I | re.M)

        if name == "info" and self.__match:
            self.__feedInfo("type", attrs.get("type"))
            self.__feedInfo("distrib", attrs.get("distrib"))
            self.__feedInfo("release", attrs.get("release"))
            self.__feedInfo("codename", attrs.get("codename"))
            self.__feedInfo("technology", attrs.get("codename"))

            self.__techVersion = sanitizeStr(attrs.get("tech_version"))
            self.__sp          = sanitizeStr(attrs.get("sp"))

            if self.__techVersion.isdigit():
                self.__feedInfo("techVersion", self.__match.group(int(self.__techVersion)))

            if self.__sp.isdigit():
                self.__feedInfo("sp", "Service Pack %s" % self.__match.group(int(self.__sp)))

            self.__regexp      = None
            self.__match       = None
            self.__techVersion = None


def headersParser(headers):
    """
    This function calls a class that parses the input HTTP headers to
    fingerprint the back-end database management system operating system
    and the web application technology
    """

    # TODO: ahead here
    topHeaders = {
                   #"cookie":                          "%s/cookie.xml" % paths.SQLMAP_XML_BANNER_PATH,
                   #"microsoftsharepointteamservices": "%s/microsoftsharepointteamservices.xml" % paths.SQLMAP_XML_BANNER_PATH,
                   #"server":                          "%s/server.xml" % paths.SQLMAP_XML_BANNER_PATH,
                   #"servlet-engine":                  "%s/servlet-engine.xml" % paths.SQLMAP_XML_BANNER_PATH,
                   #"set-cookie":                      "%s/cookie.xml" % paths.SQLMAP_XML_BANNER_PATH,
                   #"www-authenticate":                "%s/www-authenticate.xml" % paths.SQLMAP_XML_BANNER_PATH,
                   #"x-aspnet-version":                "%s/x-aspnet-version.xml" % paths.SQLMAP_XML_BANNER_PATH,
                   "x-powered-by":                    "%s/x-powered-by.xml" % paths.SQLMAP_XML_BANNER_PATH,
                 }

    for header in headers:
        if header in topHeaders.keys():
            value = headers[header]
            xmlfile = topHeaders[header]
            checkFile(xmlfile)
            handler = HeadersHandler(value)
            parse(xmlfile, handler)
            parse(paths.GENERIC_XML, handler)
