#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTPHEADER

__product__ = "Airlock (Phion/Ergon)"

def detect(get_page):
    page, headers, code = get_page()
    return re.search(r"\AAL[_-]?(SESS|LB)=", headers.get(HTTPHEADER.SET_COOKIE, ""), re.I) is not None
