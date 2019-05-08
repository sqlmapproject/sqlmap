#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Approach Web Application Firewall (Approach)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval |= re.search(r"Approach Web Application Firewall", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        retval |= re.search(r"Approach(</b>)? Web Application Firewall", page or "", re.I) is not None
        retval |= " Your IP address has been logged and this information could be used by authorities to track you." in (page or "")
        retval |= all(_ in (page or "") for _ in ("Sorry for the inconvenience!", "If this was an legitimate request please contact us with details!"))
        if retval:
            break

    return retval
