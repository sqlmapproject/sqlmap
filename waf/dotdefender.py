#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "dotDefender (Applicure Technologies)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retVal = headers.get("X-dotDefender-denied", "") == "1"
        if retVal:
            break

    return retval
