#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "BIG-IP Application Security Manager (F5 Networks)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        _, headers, code = get_page(get=vector)
        retval = headers.get("X-Cnection", "").lower() == "close"
        retval |= headers.get("X-WA-Info") is not None
        retval |= re.search(r"\bTS[0-9a-f]+=", headers.get(HTTP_HEADER.SET_COOKIE, "")) is not None
        retval |= re.search(r"BigIP|BIGipServer", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None
        retval |= re.search(r"BigIP|BIGipServer", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        retval |= re.search(r"\AF5\Z", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        retval &= code >= 400
        if retval:
            break

    return retval
