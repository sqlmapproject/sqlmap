#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "WTS Web Application Firewall"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval = re.search(r"wts(.*)?", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        retval |= all(_ in (page or "") for _ in ("<title>WTS.WAF", "<h1>WTS-WAF"))
        if retval:
            break

    return retval
