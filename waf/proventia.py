#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.data import kb
from lib.core.enums import HTTPHEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Proventia Web Application Security (IBM)"

def detect(get_page):
    page, headers, code = get_page()
    if page is None:
        return False
    page, headers, code = get_page(url="/Admin_Files/")
    return page is None
