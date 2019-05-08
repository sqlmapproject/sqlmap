#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "WP Cerber Security (Cerber Tech)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval |= any(_ in (page or "") for _ in ("We're sorry, you are not allowed to proceed", "Your request looks suspicious or similar to automated requests from spam posting software"))
        if retval:
            break

    return retval
