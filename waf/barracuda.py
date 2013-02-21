#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTPHEADER

__product__ = "Barracuda Web Application Firewall (Barracuda Networks)"

def detect(get_page):
    page, headers, code = get_page()
    return re.search(r"\Abarra_counter_session=", headers.get(HTTPHEADER.SET_COOKIE, ""), re.I) is not None
