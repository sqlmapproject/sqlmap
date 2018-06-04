#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Anquanbao Web Application Firewall (Anquanbao)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval = re.search(r"MISS", headers.get("X-Powered-By-Anquanbao", ""), re.I) is not None
        retval |= code == 405 and any(_ in (page or "") for _ in ("/aqb_cc/error/", "hidden_intercept_time"))
        if retval:
            break

    return retval
