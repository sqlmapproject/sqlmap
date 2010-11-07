#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.agent import agent
from lib.core.common import getInjectionCase
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapNoneDataException
from lib.core.session import setParenthesis
from lib.request.connect import Connect as Request

def checkForParenthesis():
    """
    This method checks if the SQL injection affected parameter
    is within the parenthesis.
    """

    logMsg = "testing for parenthesis on injectable parameter"
    logger.info(logMsg)

    logic = conf.logic
    count = 0
    case = getInjectionCase(kb.injType)

    if case is None:
        raise sqlmapNoneDataException, "unsupported injection type"

    if kb.parenthesis is not None:
        return

    if conf.prefix or conf.postfix:
        kb.parenthesis = 0
        return

    for parenthesis in range(1, 4):
        randInt = randomInt()
        randStr = randomStr()

        query = case.usage.prefix.format % eval(case.usage.prefix.params)
        query = query[:-1] + case.usage.postfix.format % eval(case.usage.postfix.params)

        payload = agent.payload(newValue=query)
        result = Request.queryPage(payload)

        if result:
            count = parenthesis

    logMsg = "the injectable parameter requires %d parenthesis" % count
    logger.info(logMsg)

    setParenthesis(count)
