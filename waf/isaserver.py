#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.common import randomInt

__product__ = "ISA Server (Microsoft)"

def detect(get_page):
    page, _, _ = get_page(host=randomInt(6))
    retval = "The server denied the specified Uniform Resource Locator (URL). Contact the server administrator." in (page or "")
    retval |= "The ISA Server denied the specified Uniform Resource Locator (URL)" in (page or "")
    return retval
