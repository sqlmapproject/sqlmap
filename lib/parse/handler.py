#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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

from xml.sax.handler import ContentHandler

from lib.core.common import sanitizeStr
from lib.core.data import kb


class FingerprintHandler(ContentHandler):
    """
    This class defines methods to parse and extract information from
    the given DBMS banner based upon the data in XML file
    """

    def __init__(self, banner, info):
        self.__banner      = sanitizeStr(banner)
        self.__regexp      = None
        self.__match       = None
        self.__dbmsVersion = None
        self.__techVersion = None
        self.__info        = info


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
            self.__match  = re.search(self.__regexp, self.__banner, re.I | re.M)

        if name == "info" and self.__match:
            self.__feedInfo("type", attrs.get("type"))
            self.__feedInfo("distrib", attrs.get("distrib"))
            self.__feedInfo("release", attrs.get("release"))
            self.__feedInfo("codename", attrs.get("codename"))

            self.__dbmsVersion = sanitizeStr(attrs.get("dbms_version"))
            self.__techVersion = sanitizeStr(attrs.get("tech_version"))
            self.__sp          = sanitizeStr(attrs.get("sp"))

            if self.__dbmsVersion.isdigit():
                self.__feedInfo("dbmsVersion", self.__match.group(int(self.__dbmsVersion)))

            if self.__techVersion.isdigit():
                self.__feedInfo("technology", "%s %s" % (attrs.get("technology"), self.__match.group(int(self.__techVersion))))
            else:
                self.__feedInfo("technology", attrs.get("technology"))

            if self.__sp.isdigit():
                self.__feedInfo("sp", "Service Pack %s" % self.__match.group(int(self.__sp)))

            self.__regexp      = None
            self.__match       = None
            self.__dbmsVersion = None
            self.__techVersion = None
