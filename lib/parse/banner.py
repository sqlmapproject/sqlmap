#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2011 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from xml.sax.handler import ContentHandler

from lib.core.common import checkFile
from lib.core.common import getCompiledRegex
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

        self.__banner = sanitizeStr(banner)
        self.__inVersion = False
        self.__inServicePack = False
        self.__release = None
        self.__version = ""
        self.__versionAlt = None
        self.__servicePack = ""
        self.__info = info

    def __feedInfo(self, key, value):
        value = sanitizeStr(value)

        if value in ( None, "None" ):
            return

        self.__info[key] = value

    def startElement(self, name, attrs):
        if name == "signatures":
            self.__release = sanitizeStr(attrs.get("release"))

        elif name == "version":
            self.__inVersion = True

        elif name == "servicepack":
            self.__inServicePack = True

    def characters(self, data):
        if self.__inVersion:
            self.__version += sanitizeStr(data)
        elif self.__inServicePack:
            self.__servicePack += sanitizeStr(data)

    def endElement(self, name):
        if name == "signature":
            for version in (self.__version, self.__versionAlt):
                regObj = getCompiledRegex(" %s[\.\ ]+" % version)
                if version and regObj.search(self.__banner):
                    self.__feedInfo("dbmsRelease", self.__release)
                    self.__feedInfo("dbmsVersion", self.__version)
                    self.__feedInfo("dbmsServicePack", self.__servicePack)
                    break

            self.__version = ""
            self.__versionAlt = None
            self.__servicePack = ""

        elif name == "version":
            self.__inVersion = False
            self.__version = self.__version.replace(" ", "")

            regObj = getCompiledRegex(r"\A(?P<major>\d+)\.00\.(?P<build>\d+)\Z")
            match = regObj.search(self.__version)
            self.__versionAlt = "%s.0.%s.0" % (match.group('major'), match.group('build')) if match else None

        elif name == "servicepack":
            self.__inServicePack = False
            self.__servicePack = self.__servicePack.replace(" ", "")

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
