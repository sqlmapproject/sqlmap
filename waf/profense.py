#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTPHEADER

__product__ = "Profense Web Application Firewall (Armorlogic)"

def detect(get_page):
    page, headers, code = get_page()
    retval = re.search(r"Profense", headers.get(HTTPHEADER.SERVER, ""), re.I) is not None
    if not retval:
        retval = re.search(r"\APLBSID=", headers.get(HTTPHEADER.SET_COOKIE, ""), re.I) is not None
    return retval
