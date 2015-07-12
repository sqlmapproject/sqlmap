#!/usr/bin/env python

"""
Copyright (c) 2006-2015 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Sucuri WebSite Firewall"

def detect(get_page):
    retVal = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retVal = code == 403 and re.search(r"Sucuri/Cloudproxy", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        if retVal:
            break

    return retVal
