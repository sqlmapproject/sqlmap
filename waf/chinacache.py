#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "ChinaCache (ChinaCache Networks)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval = code >= 400 and headers.get("Powered-By-ChinaCache") is not None

        if retval:
            break

    return retval