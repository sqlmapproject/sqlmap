#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Distil Web Application Firewall Security (Distil Networks)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval |= headers.get("x-distil-cs") is not None
        retval |= any(_ in (page or "") for _ in ("distilCaptchaForm", "distilCallbackGuard", "cdn.distilnetworks.com/images/anomaly-detected.png"))
        if retval:
            break

    return retval
