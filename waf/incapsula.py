#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Incapsula Web Application Firewall (Incapsula/Imperva)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval = re.search(r"incap_ses|visid_incap", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None
        retval |= re.search(r"Incapsula", headers.get("X-CDN", ""), re.I) is not None
        retval |= "Incapsula incident ID" in (page or "")
        if retval:
            break

    return retval
