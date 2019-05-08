#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Virusdie (Virusdie LLC)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval |= any(_ in (page or "") for _ in ("| Virusdie</title>", "http://cdn.virusdie.ru/splash/firewallstop.png", "&copy; Virusdie.ru</p>", '<meta name="FW_BLOCK"'))
        if retval:
            break

    return retval
