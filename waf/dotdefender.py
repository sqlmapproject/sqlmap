#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "dotDefender (Applicure Technologies)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval = headers.get("X-dotDefender-denied", "") == "1"
        retval |= "dotDefender Blocked Your Request" in (page or "")
        if retval:
            break

    return retval
