#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import HTTP_HEADER
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "CloudFlare Web Application Firewall (CloudFlare)"

def detect(get_page):
    retval = False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)

        if code >= 400:
            retval |= re.search(r"cloudflare", headers.get(HTTP_HEADER.SERVER, ""), re.I) is not None
            retval |= re.search(r"\A__cfduid=", headers.get(HTTP_HEADER.SET_COOKIE, ""), re.I) is not None
            retval |= headers.get("cf-ray") is not None
            retval |= re.search(r"CloudFlare Ray ID:|var CloudFlare=", page or "") is not None
            retval |= all(_ in (page or "") for _ in ("Attention Required! | Cloudflare", "Please complete the security check to access"))
            retval |= all(_ in (page or "") for _ in ("Attention Required! | Cloudflare", "Sorry, you have been blocked"))
            retval |= any(_ in (page or "") for _ in ("CLOUDFLARE_ERROR_500S_BOX", "::CAPTCHA_BOX::"))

        if retval:
            break

    return retval
