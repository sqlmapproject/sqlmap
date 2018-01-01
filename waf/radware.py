#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "AppWall (Radware)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval = re.search(r"Unauthorized Activity Has Been Detected.+Case Number:", page or "", re.I | re.S) is not None
        retval |= headers.get("X-SL-CompState") is not None
        if retval:
            break

    return retval
