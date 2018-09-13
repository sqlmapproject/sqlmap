#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "CrawlProtect (Jean-Denis Brun)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, code = get_page(get=vector)
        retval = code >= 400 and "This site is protected by CrawlProtect" in (page or "")

    return retval
