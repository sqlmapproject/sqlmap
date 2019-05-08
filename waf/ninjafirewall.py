#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "NinjaFirewall (NinTechNet)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval |= "<title>NinjaFirewall: 403 Forbidden" in (page or "")
        retval |= all(_ in (page or "") for _ in ("For security reasons, it was blocked and logged", "NinjaFirewall"))
        if retval:
            break

    return retval
