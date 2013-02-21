#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

__product__ = "webApp.secure (webScurity)"

def detect(get_page):
    page, headers, code = get_page()
    if code == 403:
        return False
    page, headers, code = get_page(get="nx=@@")
    return code == 403
