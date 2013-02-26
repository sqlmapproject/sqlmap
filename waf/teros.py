#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTPHEADER

__product__ = "Teros/Citrix Application Firewall Enterprise (Teros/Citrix Systems)"

def detect(get_page):
    page, headers, code = get_page()
    return re.search(r"\Ast8(id|_wat|_wlf)", headers.get(HTTPHEADER.SET_COOKIE, ""), re.I) is not None
