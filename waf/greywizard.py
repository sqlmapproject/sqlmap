#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Greywizard (Grey Wizard)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, _ = get_page(get=vector)
        retval |= re.search(r"\Agreywizard", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
        retval |= any(_ in (page or "") for _ in ("We've detected attempted attack or non standard traffic from your IP address", "<title>Grey Wizard</title>"))
        if retval:
            break

    return retval
