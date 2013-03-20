#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
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
        retval |= re.search(r"static\.jiasule\.com/static/js/http_error\.js", page, re.I) is not None
        if retval:
            break

    return retval
