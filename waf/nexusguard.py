#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Nexusguard (Nexusguard Limited)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval |= "<p>Powered by Nexusguard</p>" in (page or "")
        retval |= re.search(r"speresources\.nexusguard\.com/wafpage/[^>]*#\d{3};", page or "") is not None
        if retval:
            break

    return retval
