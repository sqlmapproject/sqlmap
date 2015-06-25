#!/usr/bin/env python

"""
Copyright (c) 2006-2015 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Varnish FireWall (OWASP) "

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval = headers.get("X-Varnish") is not None
        retval |= re.search(r"varnish\Z", headers.get(HTTP_HEADER.VIA, ""), re.I) is not None
        if retval:
            break

    return retval
