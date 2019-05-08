#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "aeSecure (aeSecure)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval |= headers.get("aeSecure-code") is not None
        retval |= all(_ in (page or "") for _ in ("aeSecure", "aesecure_denied.png"))
        if retval:
            break

    return retval
