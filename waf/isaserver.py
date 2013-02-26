#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import randomInt

__product__ = "ISA Server (Microsoft)"

def detect(get_page):
    page, headers, code = get_page(host=randomInt(6))
    return "The server denied the specified Uniform Resource Locator (URL). Contact the server administrator" in page
