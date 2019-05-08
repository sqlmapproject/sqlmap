#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "onMessage Shield (Blackbaud)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval |= re.search(r"onMessage Shield", headers.get("X-Engine", ""), re.I) is not None
        retval |= "This site is protected by an enhanced security system to ensure a safe browsing experience" in (page or "")
        retval |= "onMessage SHIELD" in (page or "")
        if retval:
            break

    return retval
