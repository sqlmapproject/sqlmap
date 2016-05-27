#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Yundun Web Application Firewall (Yundun)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        _, headers, _ = get_page(get=vector)
        retval = re.search(r"YUNDUN", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        retval |= re.search(r"YUNDUN", headers.get("X-Cache", ""), re.I) is not None
        if retval:
            break

    return retval
