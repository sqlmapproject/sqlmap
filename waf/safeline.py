#!/usr/bin/env python2

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""
import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "SafeLine Next Gen Web Application Firewall (SafeLine)"

def detect(get_page):
    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        page = page or ''
        if code >= 400 and re.search(r"<!-- event_id: \w{32} -->", page) is not None and 'SafeLine' in page:
            return True

    return False
