#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Tencent Cloud Web Application Firewall (Tencent Cloud Computing)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, code = get_page(get=vector)
        retval = code == 405 and "waf.tencent-cloud.com" in (page or "")
        if retval:
            break

    return retval
