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

from xml.sax import parse
from xml.sax.handler import ContentHandler

from lib.core.common import checkFile
from lib.core.common import sanitizeStr
from lib.core.data import kb
from lib.core.data import paths

class htmlHandler(ContentHandler):
    """
    This class defines methods to parse the input HTML page to
    fingerprint the back-end database management system
    """

    def __init__(self, page):
        self.__dbms   = None
        self.__page   = page
        self.__regexp = None
        self.__match  = None

        self.dbms     = None

    def startElement(self, name, attrs):
        if name == "dbms":
            self.__dbms = attrs.get("value")

        if name == "error":
            self.__regexp = attrs.get("regexp")
            self.__match = re.search(self.__regexp, self.__page, re.I)

            if self.__match:
                self.dbms = self.__dbms
                self.__match = None

def htmlParser(page):
    """
    This function calls a class that parses the input HTML page to
    fingerprint the back-end database management system
    """

    xmlfile = paths.ERRORS_XML
    checkFile(xmlfile)
    page = sanitizeStr(page)
    handler = htmlHandler(page)
    parse(xmlfile, handler)

    if handler.dbms and handler.dbms not in kb.htmlFp:
        kb.htmlFp.append(handler.dbms)

    return handler.dbms
