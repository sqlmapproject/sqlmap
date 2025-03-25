#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import random

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def randomIP():
    octets = []

    while not octets or octets[0] in (10, 172, 192):
        octets = random.sample(xrange(1, 255), 4)

    return '.'.join(str(_) for _ in octets)

def tamper(payload, **kwargs):
    """
    Append a fake HTTP header 'X-Forwarded-For' (and alike)
    """

    headers = kwargs.get("headers", {})
    headers["X-Forwarded-For"] = randomIP()
    headers["X-Client-Ip"] = randomIP()
    headers["X-Real-Ip"] = randomIP()
    headers["CF-Connecting-IP"] = randomIP()
    headers["True-Client-IP"] = randomIP()

    # Reference: https://developer.chrome.com/multidevice/data-compression-for-isps#proxy-connection
    headers["Via"] = "1.1 Chrome-Compression-Proxy"

    # Reference: https://wordpress.org/support/topic/blocked-country-gaining-access-via-cloudflare/#post-9812007
    headers["CF-IPCountry"] = random.sample(('GB', 'US', 'FR', 'AU', 'CA', 'NZ', 'BE', 'DK', 'FI', 'IE', 'AT', 'IT', 'LU', 'NL', 'NO', 'PT', 'SE', 'ES', 'CH'), 1)[0]

    return payload
