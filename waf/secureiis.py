#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import HTTP_HEADER

__product__ = "SecureIIS Web Server Security (BeyondTrust)"

def detect(get_page):
    page, headers, code = get_page()
    retval = code != 404
    page, headers, code = get_page(auxHeaders={HTTP_HEADER.TRANSFER_ENCODING: 'a' * 1025, HTTP_HEADER.ACCEPT_ENCODING: "identity"})
    retval = retval and code == 404
    return retval
