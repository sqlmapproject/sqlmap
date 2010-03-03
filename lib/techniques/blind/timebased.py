#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2010 Bernardo Damele A. G. <bernardo.damele@gmail.com>
Copyright (c) 2006 Daniele Bellucci <daniele.bellucci@gmail.com>

sqlmap is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 2 of the License.

sqlmap is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with sqlmap; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

import time

from lib.core.agent import agent
from lib.core.common import getDelayQuery
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.request import inject
from lib.request.connect import Connect as Request

def timeTest():
    infoMsg  = "testing time based blind sql injection on parameter "
    infoMsg += "'%s' with AND condition syntax" % kb.injParameter
    logger.info(infoMsg)

    timeQuery = getDelayQuery(andCond=True)
    query     = agent.prefixQuery(" AND %s" % timeQuery)
    query     = agent.postfixQuery(query)
    payload   = agent.payload(newValue=query)
    start     = time.time()
    _         = Request.queryPage(payload)
    duration  = int(time.time() - start)

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
        duration   = int(time.time() - start)

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
    duration   = int(time.time() - start)

    return duration
