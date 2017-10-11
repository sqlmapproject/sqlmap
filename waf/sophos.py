#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "UTM Web Protection (Sophos)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval = "Powered by UTM Web Protection" in (page or "")
        if retval:
            break

    return retval
