#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import time

from lib.core.common import calculateDeltaSeconds
from lib.core.common import getDelayQuery
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.session import setStacked
from lib.request import inject

def stackedTest():
    if conf.direct:
        return

    if kb.stackedTest is not None:
        return kb.stackedTest

    infoMsg  = "testing stacked queries sql injection on parameter "
    infoMsg += "'%s'" % kb.injParameter
    logger.info(infoMsg)

    query      = getDelayQuery()
    start      = time.time()
    payload, _ = inject.goStacked(query)
    duration   = calculateDeltaSeconds(start)

    if duration >= conf.timeSec:
        infoMsg  = "the target url is affected by a stacked queries "
        infoMsg += "sql injection on parameter '%s'" % kb.injParameter
        logger.info(infoMsg)

        kb.stackedTest = payload
    else:
        warnMsg  = "the target url is not affected by a stacked queries "
        warnMsg += "sql injection on parameter '%s'" % kb.injParameter
        logger.warn(warnMsg)

        kb.stackedTest = False

    setStacked()

    return kb.stackedTest
