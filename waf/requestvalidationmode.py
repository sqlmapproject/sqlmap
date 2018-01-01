#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "ASP.NET RequestValidationMode (Microsoft)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, _, code = get_page(get=vector)
        retval = "ASP.NET has detected data in the request that is potentially dangerous" in (page or "")
        retval |= "Request Validation has detected a potentially dangerous client input value" in (page or "")
        retval |= code == 500 and "HttpRequestValidationException" in page
        if retval:
            break

    return retval
