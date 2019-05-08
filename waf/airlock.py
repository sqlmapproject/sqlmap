#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Airlock (Phion/Ergon)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval |= re.search(r"\AAL[_-]?(SESS|LB)", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None
        retval |= all(_ in (page or "") for _ in ("The server detected a syntax error in your request", "Check your request and all parameters", "Bad Request", "Your request ID was"))
        if retval:
            break

    return retval
