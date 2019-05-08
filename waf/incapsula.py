#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Incapsula Web Application Firewall (Incapsula/Imperva)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval |= re.search(r"incap_ses|visid_incap", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None
        retval |= re.search(r"Incapsula", headers.get("X-CDN", ""), re.I) is not None
        retval |= "Incapsula incident ID" in (page or "")
        retval |= all(_ in (page or "") for _ in ("Error code 15", "This request was blocked by the security rules"))
        retval |= re.search(r"(?i)incident.{1,100}?\b\d{19}\-\d{17}\b", page or "") is not None
        retval |= headers.get("X-Iinfo") is not None
        if retval:
            break

    return retval
