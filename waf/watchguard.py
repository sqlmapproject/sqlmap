#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "WatchGuard (WatchGuard Technologies)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval |= (code or 0) >= 400 and re.search(r"\AWatchGuard", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        retval |= "Request denied by WatchGuard Firewall" in (page or "")
        if retval:
            break

    return retval
