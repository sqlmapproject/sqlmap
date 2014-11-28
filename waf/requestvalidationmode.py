#!/usr/bin/env python

"""
Copyright (c) 2006-2014 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import randomInt

__product__ = "ASP.NET RequestValidationMode (Microsoft)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retval = re.search(r"ASP\.NET has detected data in the request that is potentially dangerous", page, re.I) is not None
        if retval:
            break

    return retval
