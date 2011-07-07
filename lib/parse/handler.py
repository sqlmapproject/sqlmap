#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re
from xml.sax.handler import ContentHandler
from lib.core.common import sanitizeStr

class FingerprintHandler(ContentHandler):
    """
    This class defines methods to parse and extract information from
    the given DBMS banner based upon the data in XML file
    """

    def __init__(self, banner, info):
        ContentHandler.__init__(self)

        self.__banner = sanitizeStr(banner)
        self.__regexp = None
        self.__match = None
        self.__dbmsVersion = None
        self.__techVersion = None
        self.__info = info

    def __feedInfo(self, key, value):
        value = sanitizeStr(value)

        if value in ( None, "None" ):
            return

        if key in ( "dbmsVersion" ):
            self.__info[key] = value
        else:
            if key not in self.__info.keys():
                self.__info[key] = set()

            for v in value.split("|"):
                self.__info[key].add(v)

    def startElement(self, name, attrs):
        if name == "regexp":
            self.__regexp = sanitizeStr(attrs.get("value"))
            self.__match = re.search(self.__regexp, self.__banner, re.I | re.M)

        if name == "info" and self.__match:
            self.__feedInfo("type", attrs.get("type"))
            self.__feedInfo("distrib", attrs.get("distrib"))
            self.__feedInfo("release", attrs.get("release"))
            self.__feedInfo("codename", attrs.get("codename"))

            self.__dbmsVersion = sanitizeStr(attrs.get("dbms_version"))
            self.__techVersion = sanitizeStr(attrs.get("tech_version"))
            self.__sp = sanitizeStr(attrs.get("sp"))

            if self.__dbmsVersion.isdigit():
                self.__feedInfo("dbmsVersion", self.__match.group(int(self.__dbmsVersion)))

            if self.__techVersion.isdigit():
                self.__feedInfo("technology", "%s %s" % (attrs.get("technology"), self.__match.group(int(self.__techVersion))))
            else:
                self.__feedInfo("technology", attrs.get("technology"))

            if self.__sp.isdigit():
                self.__feedInfo("sp", "Service Pack %s" % self.__match.group(int(self.__sp)))

            self.__regexp = None
            self.__match = None
            self.__dbmsVersion = None
            self.__techVersion = None
