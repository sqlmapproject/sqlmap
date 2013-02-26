#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTPHEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "TrafficShield (F5 Networks)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval = re.search(r"F5-TrafficShield", headers.get(HTTPHEADER.SERVER, ""), re.I) is not None
        retval |= re.search(r"\AASINFO=", headers.get(HTTPHEADER.SET_COOKIE, ""), re.I) is not None
        if retval:
            break

    return retval
