#!/usr/bin/env python

"""
$Id: banner.py 214 2008-07-14 14:17:06Z inquisb $

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


class bannerHandler(ContentHandler):
    """
    This class defines methods to parse and extract information from
    the given DBMS banner based upon the data in XML file
    """

    def __init__(self, banner):
        self.__banner        = sanitizeStr(banner)
        self.release         = None
        self.version         = None
        self.servicePack     = None
        self.__inVersion     = False
        self.__inServicePack = False
        self.__release       = None
        self.__version       = ""
        self.__servicePack   = ""


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
                self.release     = self.__release
                self.version     = self.__version
                self.servicePack = self.__servicePack

            self.__version     = ""
            self.__servicePack = ""


        elif name == "version":
            self.__inVersion = False
            self.__version = self.__version.replace(" ", "")

        elif name == "servicepack":
            self.__inServicePack = False
            self.__servicePack = self.__servicePack.replace(" ", "")



def bannerParser(banner, xmlfile):
    """
    This function calls a class to extract information from the given
    DBMS banner based upon the data in XML file
    """

    checkFile(xmlfile)
    banner = sanitizeStr(banner)
    handler = bannerHandler(banner)
    parse(xmlfile, handler)

    return handler.release, handler.version, handler.servicePack
