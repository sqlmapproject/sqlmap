#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Jiasule Web Application Firewall (Jiasule)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval = re.search(r"jiasule-WAF", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        retval |= re.search(r"__jsluid=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None
        retval |= re.search(r"jsl_tracking", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None
        retval |= re.search(r"static\.jiasule\.com/static/js/http_error\.js", page or "", re.I) is not None
        retval |= code == 403 and "notice-jiasule" in (page or "")
        if retval:
            break

    return retval
