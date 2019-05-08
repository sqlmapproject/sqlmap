#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "NetScaler AppFirewall (Citrix)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval |= any(_ in (page or "") for _ in ("<title>Application Firewall Block Page</title>", "Violation Category: APPFW_", "AppFW Session ID", "Access has been blocked - if you feel this is in error, please contact the site administrators quoting the following"))
        if retval:
            break

    return retval
