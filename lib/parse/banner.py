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

import re

from xml.sax import parse
from xml.sax.handler import ContentHandler

from lib.core.common import checkFile
from lib.core.common import sanitizeStr
from lib.core.data import kb
from lib.core.data import paths
from lib.parse.handler import FingerprintHandler

class MSSQLBannerHandler(ContentHandler):
    """
    This class defines methods to parse and extract information from the
    given Microsoft SQL Server banner based upon the data in XML file
    """

    def __init__(self, banner, info):
        self.__banner        = sanitizeStr(banner)
        self.__inVersion     = False
        self.__inServicePack = False
        self.__release       = None
        self.__version       = ""
        self.__versionAlt    = None
        self.__servicePack   = ""
        self.__info          = info

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
                if version and re.search(" %s[\.\ ]+" % version, self.__banner):
                    self.__feedInfo("dbmsRelease", self.__release)
                    self.__feedInfo("dbmsVersion", self.__version)
                    self.__feedInfo("dbmsServicePack", self.__servicePack)
                    break

            self.__version     = ""
            self.__versionAlt  = None
            self.__servicePack = ""

        elif name == "version":
            self.__inVersion = False
            self.__version = self.__version.replace(" ", "")
            
            match = re.search(r"\A(?P<major>\d+)\.00\.(?P<build>\d+)\Z", self.__version)
            self.__versionAlt = "%s.0.%s.0" % (match.group('major'), match.group('build')) if match else None

        elif name == "servicepack":
            self.__inServicePack = False
            self.__servicePack = self.__servicePack.replace(" ", "")

def bannerParser(banner):
    """
    This function calls a class to extract information from the given
    DBMS banner based upon the data in XML file
    """

    if kb.dbms == "Microsoft SQL Server":
        xmlfile = paths.MSSQL_XML
    elif kb.dbms == "MySQL":
        xmlfile = paths.MYSQL_XML
    elif kb.dbms == "Oracle":
        xmlfile = paths.ORACLE_XML
    elif kb.dbms == "PostgreSQL":
        xmlfile = paths.PGSQL_XML

    checkFile(xmlfile)

    if kb.dbms == "Microsoft SQL Server":
        handler = MSSQLBannerHandler(banner, kb.bannerFp)
        parse(xmlfile, handler)

        handler = FingerprintHandler(banner, kb.bannerFp)
        parse(paths.GENERIC_XML, handler)
    else:
        handler = FingerprintHandler(banner, kb.bannerFp)
        parse(xmlfile, handler)
        parse(paths.GENERIC_XML, handler)
