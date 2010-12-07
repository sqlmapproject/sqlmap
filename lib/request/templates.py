#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.data import kb
from lib.request.connect import Connect as Request

def getPageTemplate(payload, place):
    retVal = kb.originalPage
    if payload and place:
        if (payload, place) not in kb.pageTemplates:
            kb.pageTemplates[(payload, place)], _ = Request.queryPage(payload, place, content=True)
        retVal = kb.pageTemplates[(payload, place)]
    return retVal
