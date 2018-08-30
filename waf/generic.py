#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.data import kb
from lib.core.settings import GENERIC_PROTECTION_REGEX
from lib.core.settings import IDS_WAF_CHECK_PAYLOAD
from lib.core.settings import WAF_ATTACK_VECTORS

__product__ = "Generic (Unknown)"

def detect(get_page):
    retval = False

    original, _, code = get_page()
    if original is None or code >= 400:
        return False

    for vector in WAF_ATTACK_VECTORS:
        page, headers, code = get_page(get=vector)

        if code >= 400 or (IDS_WAF_CHECK_PAYLOAD in vector and (code is None or re.search(GENERIC_PROTECTION_REGEX, page or "") and not re.search(GENERIC_PROTECTION_REGEX, original or ""))):
            if code is not None:
                kb.wafSpecificResponse = "HTTP/1.1 %s\n%s\n%s" % (code, "".join(_ for _ in (headers.headers if headers else {}) or [] if not _.startswith("URI")), page)

            retval = True
            break

    return retval
