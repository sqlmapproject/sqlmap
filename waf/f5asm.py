#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.enums import HTTPHEADER

__product__ = "F5 Networks BIG-IP Application Security Manager (ASM)"
__request__ = ()

def detect(page, headers, code):
    return re.search(r"^TS[a-zA-Z0-9]{3,6}=", headers.get(HTTPHEADER.SET_COOKIE, "")) is not None
