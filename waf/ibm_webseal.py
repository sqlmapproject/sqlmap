#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "IBM Security Access Manager for Web WebSEAL."

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        _, headers, _ = get_page(get=vector)
        retval = re.search(r"WebSEAL/9.0.5.0", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
	retval |= "The Access Manager WebSEAL server received an invalid HTTP request." in (page or "") is not None
        if retval:
            break

    return retval
