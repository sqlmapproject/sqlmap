#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Safedog Web Application Firewall (Safedog)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval |= re.search(r"WAF/2\.0", headers.get(HTTP_HEADER.X_POWERED_BY, ""), re.I) is not None
        retval |= re.search(r"Safedog", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        retval |= re.search(r"safedog", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None
        retval |= any(_ in (page or "") for _ in ("safedogsite/broswer_logo.jpg", "404.safedog.cn/sitedog_stat.html"))
        if retval:
            break

    return retval
