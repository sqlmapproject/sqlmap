#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "MalCare (Inactiv.com Media Solutions Pvt Ltd.)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, _ = get_page(get=vector)
        retval |= "Blocked because of Malicious Activities" in (page or "")
        retval |= re.search(r"Firewall(<[^>]+>)*powered by(<[^>]+>)*MalCare", page or "") is not None
        if retval:
            break

    return retval
