#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "SonicWALL (Dell)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval = "This request is blocked by the SonicWALL" in (page or "")
        retval |= all(_ in (page or "") for _ in ("#shd", "#nsa_banner"))
        retval |= re.search(r"Web Site Blocked.+\bnsa_banner", page or "", re.I) is not None
        retval |= re.search(r"SonicWALL", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        if retval:
            break

    return retval
