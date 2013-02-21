#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

__product__ = "IBM WebSphere DataPower (IBM)"

def detect(get_page):
    page, headers, code = get_page()
    return re.search(r"\A(OK|FAIL)", headers.get("X-Backside-Transport", ""), re.I) is not None
