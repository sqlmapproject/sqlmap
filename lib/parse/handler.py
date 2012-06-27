#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
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

        self._banner = sanitizeStr(banner)
        self._regexp = None
        self._match = None
        self._dbmsVersion = None
        self._techVersion = None
        self._info = info

    def _feedInfo(self, key, value):
        value = sanitizeStr(value)

        if value in ( None, "None" ):
            return

        if key == "dbmsVersion":
            self._info[key] = value
        else:
            if key not in self._info.keys():
                self._info[key] = set()

            for _ in value.split("|"):
                self._info[key].add(_)

    def startElement(self, name, attrs):
        if name == "regexp":
            self._regexp = sanitizeStr(attrs.get("value"))
            _ = re.match("\A[A-Za-z0-9]+", self._regexp) # minor trick avoiding compiling of large amount of regexes

            if _ and _.group(0).lower() in self._banner.lower() or not _:
                self._match = re.search(self._regexp, self._banner, re.I | re.M)
            else:
                self._match = None

        if name == "info" and self._match:
            self._feedInfo("type", attrs.get("type"))
            self._feedInfo("distrib", attrs.get("distrib"))
            self._feedInfo("release", attrs.get("release"))
            self._feedInfo("codename", attrs.get("codename"))

            self._dbmsVersion = sanitizeStr(attrs.get("dbms_version"))
            self._techVersion = sanitizeStr(attrs.get("tech_version"))
            self._sp = sanitizeStr(attrs.get("sp"))

            if self._dbmsVersion.isdigit():
                self._feedInfo("dbmsVersion", self._match.group(int(self._dbmsVersion)))

            if self._techVersion.isdigit():
                self._feedInfo("technology", "%s %s" % (attrs.get("technology"), self._match.group(int(self._techVersion))))
            else:
                self._feedInfo("technology", attrs.get("technology"))

            if self._sp.isdigit():
                self._feedInfo("sp", "Service Pack %s" % self._match.group(int(self._sp)))

            self._regexp = None
            self._match = None
            self._dbmsVersion = None
            self._techVersion = None
