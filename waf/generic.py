#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.convert import getUnicode
from lib.core.data import kb
from lib.core.settings import GENERIC_PROTECTION_REGEX
from lib.core.settings import IPS_WAF_CHECK_PAYLOAD
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Generic (Unknown)"

def detect(get_page):
    retval = False

    original, _, code = get_page()
    if original is None or (code or 0) >= 400:
        return False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)

        if (code or 0) >= 400 or (IPS_WAF_CHECK_PAYLOAD in vector and (code is None or re.search(GENERIC_PROTECTION_REGEX, page or "") and not re.search(GENERIC_PROTECTION_REGEX, original or ""))):
            if code is not None:
                kb.wafSpecificResponse = "HTTP/1.1 %s\n%s\n%s" % (code, "".join(getUnicode(_) for _ in (headers.headers if headers else {}) or [] if not _.startswith("URI")), getUnicode(page or ""))

            retval = True
            break

    return retval
