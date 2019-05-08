#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Bekchy (Faydata Information Technologies Inc.)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval |= any(_ in (page or "") for _ in ("<title>Bekchy - Access Denided</title>", "<a class=\"btn\" href=\"https://bekchy.com/report\">"))
        if retval:
            break

    return retval
