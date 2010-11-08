#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import time

from lib.core.agent import agent
from lib.core.common import getUnicode
from lib.core.common import randomInt
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.session import setError
from lib.request import inject

def errorTest():
    if conf.direct:
        return

    if kb.errorTest is not None:
        return kb.errorTest

    infoMsg  = "testing error-based sql injection on parameter "
    infoMsg += "'%s' with %s condition syntax" % (kb.injParameter, conf.logic)
    logger.info(infoMsg)

    randInt = getUnicode(randomInt(1))
    query = queries[kb.dbms].case.query % ("%s=%s" % (randInt, randInt))
    result, usedPayload = inject.goError(query, suppressOutput=True, returnPayload=True)

    if result:
        infoMsg  = "the target url is affected by an error-based sql "
        infoMsg += "injection on parameter '%s'" % kb.injParameter
        logger.info(infoMsg)

        kb.errorTest = agent.removePayloadDelimiters(usedPayload, False)
    else:
        warnMsg  = "the target url is not affected by an error-based sql "
        warnMsg += "injection on parameter '%s'" % kb.injParameter
        logger.warn(warnMsg)

        kb.errorTest = False

    setError()

    return kb.errorTest
