#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Application Security Manager (F5 Networks)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval = "The requested URL was rejected. Please consult with your administrator." in (page or "")
        retval |= all(_ in (page or "") for _ in ("This page can't be displayed. Contact support for additional information", "The incident ID is:"))
        retval |= re.search(r"(?i)Support.ID", page or "") is not None and re.search(r"\b\d{19}\b", page or "") is not None
        if retval:
            break

    return retval
