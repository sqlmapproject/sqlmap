#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os

from lib.core.common import checkFile
from lib.core.common import parseXmlFile
from lib.core.data import kb
from lib.core.data import paths
from lib.parse.handler import FingerprintHandler

def headersParser(headers):
    """
    This function calls a class that parses the input HTTP headers to
    fingerprint the back-end database management system operating system
    and the web application technology
    """

    topHeaders = {
                   "cookie":                          os.path.join(paths.SQLMAP_XML_BANNER_PATH, "cookie.xml"),
                   "microsoftsharepointteamservices": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "sharepoint.xml"),
                   "server":                          os.path.join(paths.SQLMAP_XML_BANNER_PATH, "server.xml"),
                   "servlet-engine":                  os.path.join(paths.SQLMAP_XML_BANNER_PATH, "servlet.xml"),
                   "set-cookie":                      os.path.join(paths.SQLMAP_XML_BANNER_PATH, "cookie.xml"),
                   "x-aspnet-version":                os.path.join(paths.SQLMAP_XML_BANNER_PATH, "x-aspnet-version.xml"),
                   "x-powered-by":                    os.path.join(paths.SQLMAP_XML_BANNER_PATH, "x-powered-by.xml")
                 }

    for header in headers:
        if header in topHeaders:
            value = headers[header]
            xmlfile = topHeaders[header]

            checkFile(xmlfile)

            handler = FingerprintHandler(value, kb.headersFp)

            parseXmlFile(xmlfile, handler)
            parseXmlFile(paths.GENERIC_XML, handler)
