#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Generic (Unknown)"

def detect(get_page):
    retval = False

    page, _, code = get_page()
    if page is None or code >= 400:
        return False

    for vector in WAF_ATTACK_VECTORS:
        page, _, code = get_page(get=vector)

        if code >= 400:
            retval = True
            break

    return retval
