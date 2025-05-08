#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    HTML encode (using code points) all non-alphanumeric characters (e.g. ' -> &#39;)

    >>> tamper("1' AND SLEEP(5)#")
    '1&#39;&#32;AND&#32;SLEEP&#40;5&#41;&#35;'
    >>> tamper("1&#39;&#32;AND&#32;SLEEP&#40;5&#41;&#35;")
    '1&#39;&#32;AND&#32;SLEEP&#40;5&#41;&#35;'
    """

    if payload:
        payload = re.sub(r"&#(\d+);", lambda match: chr(int(match.group(1))), payload)      # NOTE: https://github.com/sqlmapproject/sqlmap/issues/5203
        payload = re.sub(r"[^\w]", lambda match: "&#%d;" % ord(match.group(0)), payload)

    return payload
