#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "CloudProxy WebSite Firewall (Sucuri)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval = code == 403 and re.search(r"Sucuri/Cloudproxy", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        retval |= "Access Denied - Sucuri Website Firewall" in (page or "")
        retval |= "Sucuri WebSite Firewall - CloudProxy - Access Denied" in (page or "")
        retval |= re.search(r"Questions\?.+cloudproxy@sucuri\.net", (page or "")) is not None
        if retval:
            break

    return retval
