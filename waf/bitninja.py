#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "BitNinja (BitNinja)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval |= any(_ in (page or "") for _ in ("alt=\"BitNinja|Security check by BitNinja", "your IP will be removed from BitNinja", "<title>Visitor anti-robot validation</title>"))
        if retval:
            break

    return retval
