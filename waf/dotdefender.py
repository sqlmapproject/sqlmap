#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "dotDefender (Applicure Technologies)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval = headers.get("X-dotDefender-denied", "") == "1"
        retval |= any(_ in (page or "") for _ in ("dotDefender Blocked Your Request", '<meta name="description" content="Applicure is the leading provider of web application security', "Please contact the site administrator, and provide the following Reference ID:"))
        if retval:
            break

    return retval
