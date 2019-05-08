#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "360 Web Application Firewall (360)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval |= headers.get("X-Powered-By-360wzb") is not None
        retval |= code == 493 and "/wzws-waf-cgi/" in (page or "")
        retval |= all(_ in (page or "") for _ in ("eventID", "If you are the Webmaster", "<title>493</title>"))
        if retval:
            break

    return retval
