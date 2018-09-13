#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "CloudFront (Amazon)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        _, headers, _ = get_page(get=vector)

        retval = re.search(r"Error from cloudfront", headers.get("X-Cache", ""), re.I) is not None

        if retval:
            break

    return retval
