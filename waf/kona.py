#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "KONA Security Solutions (Akamai Technologies)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, code = get_page(get=vector)
        retval = code in (400, 501) and re.search(r"Reference #[0-9A-Fa-f.]+", page, re.I) is not None
        if retval:
            break

    return retval
