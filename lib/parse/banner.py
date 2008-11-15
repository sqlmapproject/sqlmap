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


class BannerHandler(ContentHandler):
    """
    This class defines methods to parse and extract information from
    the given DBMS banner based upon the data in XML file
    """

    def __init__(self, banner):
        self.__banner   = sanitizeStr(banner)

        self.__regexp   = None
        self.__match    = None
        self.__position = None

        self.info       = {}


    def startElement(self, name, attrs):
        if name == "regexp":
            self.__regexp = sanitizeStr(attrs.get("value"))
            self.__match  = re.search(self.__regexp, self.__banner, re.I | re.M)

        if name == "info" and self.__match:
            self.__position = sanitizeStr(attrs.get("version"))
            self.__sp       = sanitizeStr(attrs.get("sp"))

            self.info['type']     = sanitizeStr(attrs.get("type"))
            self.info['distrib']  = sanitizeStr(attrs.get("distrib"))
            self.info['release']  = sanitizeStr(attrs.get("release"))
            self.info['codename'] = sanitizeStr(attrs.get("codename"))

            if self.__position.isdigit():
                self.info['version'] = self.__match.group(int(self.__position))

            if self.__sp.isdigit():
                self.info['sp'] = "Service Pack %s" % self.__match.group(int(self.__sp))

            self.__match    = None
            self.__position = None


class MSSQLBannerHandler(ContentHandler):
    """
    This class defines methods to parse and extract information from the
    given Microsoft SQL Server banner based upon the data in XML file
    """

    def __init__(self, banner):
        self.__banner        = sanitizeStr(banner)

        self.__inVersion     = False
        self.__inServicePack = False
        self.__release       = None
        self.__version       = ""
        self.__servicePack   = ""

        self.info            = {}


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
            if re.search(" %s[\.\ ]+" % self.__version, self.__banner):
                self.info['dbmsRelease']     = self.__release
                self.info['dbmsVersion']     = self.__version
                self.info['dbmsServicePack'] = self.__servicePack

            self.__version     = ""
            self.__servicePack = ""


        elif name == "version":
            self.__inVersion = False
            self.__version = self.__version.replace(" ", "")

        elif name == "servicepack":
            self.__inServicePack = False
            self.__servicePack = self.__servicePack.replace(" ", "")


def bannerParser(banner):
    """
    This function calls a class to extract information from the given
    DBMS banner based upon the data in XML file
    """

    banner = sanitizeStr(banner)
    info   = {}

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
        handler = MSSQLBannerHandler(banner)
        parse(xmlfile, handler)
        info = handler.info

        handler = BannerHandler(banner)
        parse(paths.GENERIC_XML, handler)

        for title, value in handler.info.items():
            info[title] = value
    else:
        handler = BannerHandler(banner)
        parse(xmlfile, handler)
        info = handler.info

        if "type" not in info or info["type"] == "None":
            parse(paths.GENERIC_XML, handler)
            info["type"] = handler.info["type"]

        if "distrib" not in info or info["distrib"] == "None":
            parse(paths.GENERIC_XML, handler)
            info["distrib"] = handler.info["distrib"]

    return info
