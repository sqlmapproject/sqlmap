#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Deny All Web Application Firewall (DenyAll)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval = re.search(r"\Asessioncookie=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None
        retval |= code == 200 and re.search(r"\ACondition Intercepted", page or "", re.I) is not None
        if retval:
            break

    return retval
