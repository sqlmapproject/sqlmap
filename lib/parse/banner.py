#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from xml.sax.handler import ContentHandler

from lib.core.common import checkFile
from lib.core.common import Backend
from lib.core.common import parseXmlFile
from lib.core.common import sanitizeStr
from lib.core.data import kb
from lib.core.data import paths
from lib.core.enums import DBMS
from lib.parse.handler import FingerprintHandler

class MSSQLBannerHandler(ContentHandler):
    """
    This class defines methods to parse and extract information from the
    given Microsoft SQL Server banner based upon the data in XML file
    """

    def __init__(self, banner, info):
        ContentHandler.__init__(self)

        self._banner = sanitizeStr(banner)
        self._inVersion = False
        self._inServicePack = False
        self._release = None
        self._version = ""
        self._versionAlt = None
        self._servicePack = ""
        self._info = info

    def _feedInfo(self, key, value):
        value = sanitizeStr(value)

        if value in ( None, "None" ):
            return

        self._info[key] = value

    def startElement(self, name, attrs):
        if name == "signatures":
            self._release = sanitizeStr(attrs.get("release"))

        elif name == "version":
            self._inVersion = True

        elif name == "servicepack":
            self._inServicePack = True

    def characters(self, data):
        if self._inVersion:
            self._version += sanitizeStr(data)
        elif self._inServicePack:
            self._servicePack += sanitizeStr(data)

    def endElement(self, name):
        if name == "signature":
            for version in (self._version, self._versionAlt):
                if version and re.search(r" %s[\.\ ]+" % version, self._banner):
                    self._feedInfo("dbmsRelease", self._release)
                    self._feedInfo("dbmsVersion", self._version)
                    self._feedInfo("dbmsServicePack", self._servicePack)
                    break

            self._version = ""
            self._versionAlt = None
            self._servicePack = ""

        elif name == "version":
            self._inVersion = False
            self._version = self._version.replace(" ", "")

            match = re.search(r"\A(?P<major>\d+)\.00\.(?P<build>\d+)\Z", self._version)
            self._versionAlt = "%s.0.%s.0" % (match.group('major'), match.group('build')) if match else None

        elif name == "servicepack":
            self._inServicePack = False
            self._servicePack = self._servicePack.replace(" ", "")

def bannerParser(banner):
    """
    This function calls a class to extract information from the given
    DBMS banner based upon the data in XML file
    """

    xmlfile = None

    if Backend.isDbms(DBMS.MSSQL):
        xmlfile = paths.MSSQL_XML
    elif Backend.isDbms(DBMS.MYSQL):
        xmlfile = paths.MYSQL_XML
    elif Backend.isDbms(DBMS.ORACLE):
        xmlfile = paths.ORACLE_XML
    elif Backend.isDbms(DBMS.PGSQL):
        xmlfile = paths.PGSQL_XML

    if not xmlfile:
        return

    checkFile(xmlfile)

    if Backend.isDbms(DBMS.MSSQL):
        handler = MSSQLBannerHandler(banner, kb.bannerFp)
        parseXmlFile(xmlfile, handler)

        handler = FingerprintHandler(banner, kb.bannerFp)
        parseXmlFile(paths.GENERIC_XML, handler)
    else:
        handler = FingerprintHandler(banner, kb.bannerFp)
        parseXmlFile(xmlfile, handler)
        parseXmlFile(paths.GENERIC_XML, handler)
