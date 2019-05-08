#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "SecureSphere Web Application Firewall (Imperva)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval |= re.search(r"<H2>Error</H2>.+?#FEEE7A.+?<STRONG>Error</STRONG>|Contact support for additional information.<br/>The incident ID is: (\\d{19}|N/A)", page or "", re.I) is not None
        if retval:
            break

    return retval
