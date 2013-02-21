#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "WebKnight Application Firewall (AQTRONIX)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)
        retVal = code == 999
        if retVal:
            break

    return retval
