#!/usr/bin/env python

import random
import os
from lib.core.common import singleTimeWarnMessage
from lib.core.common import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW


def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (
        os.path.basename(__file__).split(".")[0], DBMS.MYSQL))


def tamper(payload, **kwargs):
    """ Randomly encode some characters in a payload, will
        always encode at least three characters in the payload

        Requirement:
          * MySQL

        Tested against:
          * MySQL >= 5.0.0
          * MySQL >= 5.0.12

    """
    retVal = ""
    randomNumList = range(0, len(payload))
    acceptedEncodings = ["iso-8859-1", "iso-8859-15", "utf-8", "ascii",
                         "iso-8859-2"]
    encoded = 0
    while encoded <= 3:
        for i, c in enumerate(list(payload)):
            if i == random.choice(randomNumList):
                retVal += c.encode(random.choice(acceptedEncodings))
                encoded += 1
            else:
                retVal += c

    return retVal
