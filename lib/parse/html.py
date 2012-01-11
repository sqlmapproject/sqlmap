#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2012 sqlmap developers (http://www.sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from xml.sax.handler import ContentHandler

from lib.core.common import checkFile
from lib.core.common import parseXmlFile
from lib.core.data import kb
from lib.core.data import paths
from lib.core.threads import getCurrentThreadData

class htmlHandler(ContentHandler):
    """
    This class defines methods to parse the input HTML page to
    fingerprint the back-end database management system
    """

    def __init__(self, page):
        ContentHandler.__init__(self)

        self.__dbms = None
        self.__page = page

        self.dbms = None

    def startElement(self, name, attrs):
        if name == "dbms":
            self.__dbms = attrs.get("value")

        elif name == "error":
            if re.search(attrs.get("regexp"), self.__page, re.I):
                self.dbms = self.__dbms
                threadData = getCurrentThreadData()
                threadData.lastErrorPage = (threadData.lastRequestUID, self.__page)

def htmlParser(page):
    """
    This function calls a class that parses the input HTML page to
    fingerprint the back-end database management system
    """

    xmlfile = paths.ERRORS_XML
    checkFile(xmlfile)
    handler = htmlHandler(page)

    parseXmlFile(xmlfile, handler)

    if handler.dbms and handler.dbms not in kb.htmlFp:
        kb.lastParserStatus = handler.dbms
        kb.htmlFp.append(handler.dbms)
    else:
        kb.lastParserStatus = None

    return handler.dbms
