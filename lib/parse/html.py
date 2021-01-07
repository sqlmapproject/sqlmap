#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from xml.sax.handler import ContentHandler

from lib.core.common import urldecode
from lib.core.common import parseXmlFile
from lib.core.data import kb
from lib.core.data import paths
from lib.core.settings import HEURISTIC_PAGE_SIZE_THRESHOLD
from lib.core.threads import getCurrentThreadData

class HTMLHandler(ContentHandler):
    """
    This class defines methods to parse the input HTML page to
    fingerprint the back-end database management system
    """

    def __init__(self, page):
        ContentHandler.__init__(self)

        self._dbms = None
        self._page = (page or "")
        try:
            self._lower_page = self._page.lower()
        except SystemError:  # https://bugs.python.org/issue18183
            self._lower_page = None
        self._urldecoded_page = urldecode(self._page)

        self.dbms = None

    def _markAsErrorPage(self):
        threadData = getCurrentThreadData()
        threadData.lastErrorPage = (threadData.lastRequestUID, self._page)

    def startElement(self, name, attrs):
        if self.dbms:
            return

        if name == "dbms":
            self._dbms = attrs.get("value")

        elif name == "error":
            regexp = attrs.get("regexp")
            if regexp not in kb.cache.regex:
                keywords = re.findall(r"\w+", re.sub(r"\\.", " ", regexp))
                keywords = sorted(keywords, key=len)
                kb.cache.regex[regexp] = keywords[-1].lower()

            if ('|' in regexp or kb.cache.regex[regexp] in (self._lower_page or kb.cache.regex[regexp])) and re.search(regexp, self._urldecoded_page, re.I):
                self.dbms = self._dbms
                self._markAsErrorPage()
                kb.forkNote = kb.forkNote or attrs.get("fork")

def htmlParser(page):
    """
    This function calls a class that parses the input HTML page to
    fingerprint the back-end database management system

    >>> from lib.core.enums import DBMS
    >>> htmlParser("Warning: mysql_fetch_array() expects parameter 1 to be resource") == DBMS.MYSQL
    True
    >>> threadData = getCurrentThreadData()
    >>> threadData.lastErrorPage = None
    """

    page = page[:HEURISTIC_PAGE_SIZE_THRESHOLD]

    xmlfile = paths.ERRORS_XML
    handler = HTMLHandler(page)
    key = hash(page)

    # generic SQL warning/error messages
    if re.search(r"SQL (warning|error|syntax)", page, re.I):
        handler._markAsErrorPage()

    if key in kb.cache.parsedDbms:
        retVal = kb.cache.parsedDbms[key]
        if retVal:
            handler._markAsErrorPage()
        return retVal

    parseXmlFile(xmlfile, handler)

    if handler.dbms and handler.dbms not in kb.htmlFp:
        kb.lastParserStatus = handler.dbms
        kb.htmlFp.append(handler.dbms)
    else:
        kb.lastParserStatus = None

    kb.cache.parsedDbms[key] = handler.dbms

    return handler.dbms
