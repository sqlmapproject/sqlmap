#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import time

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

    infoMsg  = "testing error based sql injection on parameter "
    infoMsg += "'%s' with %s condition syntax" % (kb.injParameter, conf.logic)
    logger.info(infoMsg)

    randInt = getUnicode(randomInt(1))
    query = queries[kb.dbms].case.query % ("%s=%s" % (randInt, randInt))
    result = inject.goError(query)

    if result:
        infoMsg  = "the web application supports error based injection "
        infoMsg += "on parameter '%s'" % kb.injParameter
        logger.info(infoMsg)

        kb.errorTest = True
    else:
        warnMsg  = "the web application does not support error based injection "
        warnMsg += "on parameter '%s'" % kb.injParameter
        logger.warn(warnMsg)

        kb.errorTest = False

    setError()

    return kb.errorTest
