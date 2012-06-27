#!/usr/bin/env python

"""
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

        self._dbms = None
        self._page = page

        self.dbms = None

    def _markAsErrorPage(self):
        threadData = getCurrentThreadData()
        threadData.lastErrorPage = (threadData.lastRequestUID, self._page)

    def startElement(self, name, attrs):
        if name == "dbms":
            self._dbms = attrs.get("value")

        elif name == "error":
            if re.search(attrs.get("regexp"), self._page, re.I):
                self.dbms = self._dbms
                self._markAsErrorPage()

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

    # generic SQL warning/error messages
    if re.search(r"SQL (warning|error|syntax)", page, re.I):
        handler._markAsErrorPage()

    return handler.dbms
