#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import time

from lib.core.agent import agent
from lib.core.common import calculateDeltaSeconds
from lib.core.common import getDelayQuery
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.request import inject
from lib.request.connect import Connect as Request

def timeTest():
    infoMsg  = "testing time based blind sql injection on parameter "
    infoMsg += "'%s' with %s condition syntax" % (kb.injParameter, conf.logic)
    logger.info(infoMsg)

    timeQuery = getDelayQuery(andCond=True)
    query     = agent.prefixQuery("AND %s" % timeQuery)
    query     = agent.postfixQuery(query)
    payload   = agent.payload(newValue=query)
    start     = time.time()
    _         = Request.queryPage(payload)
    duration  = calculateDeltaSeconds(start)

    if duration >= conf.timeSec:
        infoMsg  = "the parameter '%s' is affected by a time " % kb.injParameter
        infoMsg += "based blind sql injection with AND condition syntax"
        logger.info(infoMsg)

        kb.timeTest = payload

    else:
        warnMsg  = "the parameter '%s' is not affected by a time " % kb.injParameter
        warnMsg += "based blind sql injection with AND condition syntax"
        logger.warn(warnMsg)

        infoMsg  = "testing time based blind sql injection on parameter "
        infoMsg += "'%s' with stacked query syntax" % kb.injParameter
        logger.info(infoMsg)

        timeQuery  = getDelayQuery(andCond=True)
        start      = time.time()
        payload, _ = inject.goStacked(timeQuery)
        duration   = calculateDeltaSeconds(start)

        if duration >= conf.timeSec:
            infoMsg  = "the parameter '%s' is affected by a time " % kb.injParameter
            infoMsg += "based blind sql injection with stacked query syntax"
            logger.info(infoMsg)

            kb.timeTest = payload
        else:
            warnMsg  = "the parameter '%s' is not affected by a time " % kb.injParameter
            warnMsg += "based blind sql injection with stacked query syntax"
            logger.warn(warnMsg)

            kb.timeTest = False

    return kb.timeTest

def timeUse(query):
    start      = time.time()
    _, _       = inject.goStacked(query)
    duration   = calculateDeltaSeconds(start)

    return duration
