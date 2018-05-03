#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import itertools
import os

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

    if not kb.headerPaths:
        kb.headerPaths = {
            "microsoftsharepointteamservices": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "sharepoint.xml"),
            "server": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "server.xml"),
            "servlet-engine": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "servlet-engine.xml"),
            "set-cookie": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "set-cookie.xml"),
            "x-aspnet-version": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "x-aspnet-version.xml"),
            "x-powered-by": os.path.join(paths.SQLMAP_XML_BANNER_PATH, "x-powered-by.xml"),
        }

    for header in itertools.ifilter(lambda _: _ in kb.headerPaths, headers):
        value = headers[header]
        xmlfile = kb.headerPaths[header]
        handler = FingerprintHandler(value, kb.headersFp)
        parseXmlFile(xmlfile, handler)
        parseXmlFile(paths.GENERIC_XML, handler)
