#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTPHEADER

__product__ = "BinarySEC Web Application Firewall (BinarySEC)"

def detect(get_page):
    page, headers, code = get_page()
    retval = re.search(r"BinarySec", headers.get(HTTPHEADER.SERVER, ""), re.I) is not None
    if not retval:
        retval = any(headers.get(_) for _ in ("x-binarysec-via", "x-binarysec-nocache"))
    return retval
