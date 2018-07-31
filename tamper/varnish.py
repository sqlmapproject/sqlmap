#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Appends a HTTP header 'X-originating-IP' to bypass Varnish Firewall

    Reference:
        * http://h30499.www3.hp.com/t5/Fortify-Application-Security/Bypassing-web-application-firewalls-using-HTTP-headers/ba-p/6418366

    Notes:
        Examples:
        >> X-forwarded-for: TARGET_CACHESERVER_IP (184.189.250.X)
        >> X-remote-IP: TARGET_PROXY_IP (184.189.250.X)
        >> X-originating-IP: TARGET_LOCAL_IP (127.0.0.1)
        >> x-remote-addr: TARGET_INTERNALUSER_IP (192.168.1.X)
        >> X-remote-IP: * or %00 or %0A
    """

    headers = kwargs.get("headers", {})
    headers["X-originating-IP"] = "127.0.0.1"
    return payload
