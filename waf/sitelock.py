#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "TrueShield Web Application Firewall (SiteLock)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval = "SiteLock Incident ID" in (page or "")
        if retval:
            break

    return retval
