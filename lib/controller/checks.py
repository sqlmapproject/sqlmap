#!/usr/bin/env python

"""
$Id$

This file is part of the sqlmap project, http://sqlmap.sourceforge.net.

Copyright (c) 2007-2009 Bernardo Damele A. G. <bernardo.damele@gmail.com>
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



import re
import time

from lib.core.agent import agent
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.convert import md5hash
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.exception import sqlmapConnectionException
from lib.core.session import setString
from lib.core.session import setRegexp
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

    randInt = randomInt()
    randStr = randomStr()

    if conf.prefix or conf.postfix:
        prefix  = ""
        postfix = ""

        if conf.prefix:
            prefix = conf.prefix

        if conf.postfix:
            postfix = conf.postfix

        infoMsg  = "testing custom injection "
        infoMsg += "on %s parameter '%s'" % (place, parameter)
        logger.info(infoMsg)

        payload = agent.payload(place, parameter, value, "%s%s%s AND %s%d=%d %s" % (value, prefix, ")" * parenthesis, "(" * parenthesis, randInt, randInt, postfix))
        trueResult = Request.queryPage(payload, place)

        if trueResult == True:
            payload = agent.payload(place, parameter, value, "%s%s%s AND %s%d=%d %s" % (value, prefix, ")" * parenthesis, "(" * parenthesis, randInt, randInt + 1, postfix))
            falseResult = Request.queryPage(payload, place)

            if falseResult != True:
                infoMsg  = "confirming custom injection "
                infoMsg += "on %s parameter '%s'" % (place, parameter)
                logger.info(infoMsg)

                payload = agent.payload(place, parameter, value, "%s%s%s AND %s%s %s" % (value, prefix, ")" * parenthesis, "(" * parenthesis, randStr, postfix))
                falseResult = Request.queryPage(payload, place)

                if falseResult != True:
                    infoMsg  = "%s parameter '%s' is " % (place, parameter)
                    infoMsg += "custom injectable "
                    logger.info(infoMsg)

                    return "custom"

    infoMsg  = "testing unescaped numeric injection "
    infoMsg += "on %s parameter '%s'" % (place, parameter)
    logger.info(infoMsg)

    payload = agent.payload(place, parameter, value, "%s%s AND %s%d=%d" % (value, ")" * parenthesis, "(" * parenthesis, randInt, randInt))
    trueResult = Request.queryPage(payload, place)

    if trueResult == True:
        payload = agent.payload(place, parameter, value, "%s%s AND %s%d=%d" % (value, ")" * parenthesis, "(" * parenthesis, randInt, randInt + 1))
        falseResult = Request.queryPage(payload, place)

        if falseResult != True:
            infoMsg  = "confirming unescaped numeric injection "
            infoMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(infoMsg)

            payload = agent.payload(place, parameter, value, "%s%s AND %s%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr))
            falseResult = Request.queryPage(payload, place)

            if falseResult != True:
                infoMsg  = "%s parameter '%s' is " % (place, parameter)
                infoMsg += "unescaped numeric injectable "
                infoMsg += "with %d parenthesis" % parenthesis
                logger.info(infoMsg)

                return "numeric"

    infoMsg  = "%s parameter '%s' is not " % (place, parameter)
    infoMsg += "unescaped numeric injectable"
    logger.info(infoMsg)

    infoMsg  = "testing single quoted string injection "
    infoMsg += "on %s parameter '%s'" % (place, parameter)
    logger.info(infoMsg)

    payload = agent.payload(place, parameter, value, "%s'%s AND %s'%s'='%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr))
    trueResult = Request.queryPage(payload, place)

    if trueResult == True:
        payload = agent.payload(place, parameter, value, "%s'%s AND %s'%s'='%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr + randomStr(1)))
        falseResult = Request.queryPage(payload, place)

        if falseResult != True:
            infoMsg  = "confirming single quoted string injection "
            infoMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(infoMsg)

            payload = agent.payload(place, parameter, value, "%s'%s and %s%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr))
            falseResult = Request.queryPage(payload, place)

            if falseResult != True:
                infoMsg  = "%s parameter '%s' is " % (place, parameter)
                infoMsg += "single quoted string injectable "
                infoMsg += "with %d parenthesis" % parenthesis
                logger.info(infoMsg)

                return "stringsingle"

    infoMsg  = "%s parameter '%s' is not " % (place, parameter)
    infoMsg += "single quoted string injectable"
    logger.info(infoMsg)

    infoMsg  = "testing LIKE single quoted string injection "
    infoMsg += "on %s parameter '%s'" % (place, parameter)
    logger.info(infoMsg)

    payload = agent.payload(place, parameter, value, "%s'%s AND %s'%s' LIKE '%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr))
    trueResult = Request.queryPage(payload, place)

    if trueResult == True:
        payload = agent.payload(place, parameter, value, "%s'%s AND %s'%s' LIKE '%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr + randomStr(1)))
        falseResult = Request.queryPage(payload, place)

        if falseResult != True:
            infoMsg  = "confirming LIKE single quoted string injection "
            infoMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(infoMsg)

            payload = agent.payload(place, parameter, value, "%s'%s and %s%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr))
            falseResult = Request.queryPage(payload, place)

            if falseResult != True:
                infoMsg  = "%s parameter '%s' is " % (place, parameter)
                infoMsg += "LIKE single quoted string injectable "
                infoMsg += "with %d parenthesis" % parenthesis
                logger.info(infoMsg)

                return "likesingle"

    infoMsg  = "%s parameter '%s' is not " % (place, parameter)
    infoMsg += "LIKE single quoted string injectable"
    logger.info(infoMsg)

    infoMsg  = "testing double quoted string injection "
    infoMsg += "on %s parameter '%s'" % (place, parameter)
    logger.info(infoMsg)

    payload = agent.payload(place, parameter, value, "%s\"%s AND %s\"%s\"=\"%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr))
    trueResult = Request.queryPage(payload, place)

    if trueResult == True:
        payload = agent.payload(place, parameter, value, "%s\"%s AND %s\"%s\"=\"%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr + randomStr(1)))
        falseResult = Request.queryPage(payload, place)

        if falseResult != True:
            infoMsg  = "confirming double quoted string injection "
            infoMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(infoMsg)

            payload = agent.payload(place, parameter, value, "%s\"%s AND %s%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr))
            falseResult = Request.queryPage(payload, place)

            if falseResult != True:
                infoMsg  = "%s parameter '%s' is " % (place, parameter)
                infoMsg += "double quoted string injectable "
                infoMsg += "with %d parenthesis" % parenthesis
                logger.info(infoMsg)

                return "stringdouble"

    infoMsg  = "%s parameter '%s' is not " % (place, parameter)
    infoMsg += "double quoted string injectable"
    logger.info(infoMsg)

    infoMsg  = "testing LIKE double quoted string injection "
    infoMsg += "on %s parameter '%s'" % (place, parameter)
    logger.info(infoMsg)

    payload = agent.payload(place, parameter, value, "%s\"%s AND %s\"%s\" LIKE \"%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr))
    trueResult = Request.queryPage(payload, place)

    if trueResult == True:
        payload = agent.payload(place, parameter, value, "%s\"%s AND %s\"%s\" LIKE \"%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr, randStr + randomStr(1)))
        falseResult = Request.queryPage(payload, place)

        if falseResult != True:
            infoMsg  = "confirming LIKE double quoted string injection "
            infoMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(infoMsg)

            payload = agent.payload(place, parameter, value, "%s\"%s and %s%s" % (value, ")" * parenthesis, "(" * parenthesis, randStr))
            falseResult = Request.queryPage(payload, place)

            if falseResult != True:
                infoMsg  = "%s parameter '%s' is " % (place, parameter)
                infoMsg += "LIKE double quoted string injectable "
                infoMsg += "with %d parenthesis" % parenthesis
                logger.info(infoMsg)

                return "likedouble"

    infoMsg  = "%s parameter '%s' is not " % (place, parameter)
    infoMsg += "LIKE double quoted string injectable"
    logger.info(infoMsg)

    return None


def checkDynParam(place, parameter, value):
    """
    This function checks if the url parameter is dynamic. If it is
    dynamic, the content of the page differs, otherwise the
    dynamicity might depend on another parameter.
    """

    infoMsg = "testing if %s parameter '%s' is dynamic" % (place, parameter)
    logger.info(infoMsg)

    randInt = randomInt()
    payload = agent.payload(place, parameter, value, str(randInt))
    dynResult1 = Request.queryPage(payload, place)

    if True == dynResult1:
        return False

    infoMsg = "confirming that %s parameter '%s' is dynamic" % (place, parameter)
    logger.info(infoMsg)

    payload = agent.payload(place, parameter, value, "'%s" % randomStr())
    dynResult2 = Request.queryPage(payload, place)

    payload = agent.payload(place, parameter, value, "\"%s" % randomStr())
    dynResult3 = Request.queryPage(payload, place)

    condition  = True != dynResult2
    condition |= True != dynResult3

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

    infoMsg = "testing if the url is stable, wait a few seconds"
    logger.info(infoMsg)

    firstPage, _ = Request.queryPage(content=True)
    time.sleep(1)
    secondPage, _ = Request.queryPage(content=True)

    condition = firstPage == secondPage

    if condition == True:
        conf.md5hash = md5hash(firstPage)

        logMsg  = "url is stable"
        logger.info(logMsg)

    elif condition == False:
        warnMsg  = "url is not stable, sqlmap will base the page "
        warnMsg += "comparison on a sequence matcher, if no dynamic nor "
        warnMsg += "injectable parameters are detected, refer to user's "
        warnMsg += "manual paragraph 'Page comparison' and provide a "
        warnMsg += "string or regular expression to match on"
        logger.warn(warnMsg)

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

    infoMsg  = "testing if the provided string is within the "
    infoMsg += "target URL page content"
    logger.info(infoMsg)

    page, _ = Request.queryPage(content=True)

    if conf.string in page:
        setString()
        return True
    else:
        errMsg  = "you provided '%s' as the string to " % conf.string
        errMsg += "match, but such a string is not within the target "
        errMsg += "URL page content, please provide another string."
        logger.error(errMsg)

        return False


def checkRegexp():
    if not conf.regexp:
        return True

    condition = (
                  kb.resumedQueries.has_key(conf.url) and
                  kb.resumedQueries[conf.url].has_key("Regular expression") and
                  kb.resumedQueries[conf.url]["Regular expression"][:-1] == conf.regexp
                )

    if condition:
        return True

    infoMsg  = "testing if the provided regular expression matches within "
    infoMsg += "the target URL page content"
    logger.info(infoMsg)

    page, _ = Request.queryPage(content=True)

    if re.search(conf.regexp, page, re.I | re.M):
        setRegexp()
        return True
    else:
        errMsg  = "you provided '%s' as the regular expression to " % conf.regexp
        errMsg += "match, but such a regular expression does not have any "
        errMsg += "match within the target URL page content, please provide "
        errMsg += "another regular expression."
        logger.error(errMsg)

        return False


def checkConnection():
    infoMsg = "testing connection to the target url"
    logger.info(infoMsg)

    try:
        page, _ = Request.getPage()
        conf.seqMatcher.set_seq1(page)

    except sqlmapConnectionException, exceptionMsg:
        exceptionMsg = str(exceptionMsg)

        if conf.multipleTargets:
            exceptionMsg += ", skipping to next url"
            logger.warn(exceptionMsg)

            return False
        else:
            raise sqlmapConnectionException, exceptionMsg

    return True
