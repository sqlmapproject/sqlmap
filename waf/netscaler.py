#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "NetScaler (Citrix Systems)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        _, headers, _ = get_page(get=vector)
        retval = re.search(r"\Aclose", headers.get("Cneonction", "") or headers.get("nnCoection", ""), re.I) is not None
        retval |= re.search(r"\A(ns_af=|citrix_ns_id|NSC_)", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None
        retval |= re.search(r"\ANS-CACHE", headers.get(HTTP_HEADER.VIA, ""), re.I) is not None
        if retval:
            break

    return retval
