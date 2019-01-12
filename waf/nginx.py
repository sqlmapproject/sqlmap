#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "NGINX Web Application Firewall (NGINX Inc.)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval = all(_ in (page or "") for _ in ("<center><h1>403 Forbidden</h1></center>", "<center>nginx</center>"))
        if retval:
            break

    return retval
