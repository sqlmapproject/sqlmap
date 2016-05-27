#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "EdgeCast WAF (Verizon)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        _, headers, code = get_page(get=vector)
        retval = code == 400 and re.search(r"\AECDF", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        if retval:
            break

    return retval
