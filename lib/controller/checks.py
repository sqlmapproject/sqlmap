#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import socket
import time

from difflib import SequenceMatcher

from lib.core.agent import agent
from lib.core.common import beep
from lib.core.common import getUnicode
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import showStaticWords
from lib.core.common import wasLastRequestDBMSError
from lib.core.common import DynamicContentItem
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NULLCONNECTION
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapGenericException
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapSiteTooDynamic
from lib.core.exception import sqlmapUserQuitException
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

    logic = conf.logic
    randInt = randomInt()
    randStr = randomStr()
    prefix = ""
    postfix = ""
    retVal = None

    if conf.prefix or conf.postfix:
        if conf.prefix:
            prefix = conf.prefix

        if conf.postfix:
            postfix = conf.postfix

    for case in kb.injections.root.case:
        conf.matchRatio = None

        positive = case.test.positive
        negative = case.test.negative

        if not prefix and not postfix and case.name == "custom":
            continue

        infoMsg  = "testing %s (%s) injection " % (case.desc, logic)
        infoMsg += "on %s parameter '%s'" % (place, parameter)
        logger.info(infoMsg)

        payload = agent.payload(place, parameter, value, negative.format % eval(negative.params))
        _ = Request.queryPage(payload, place)

        payload = agent.payload(place, parameter, value, positive.format % eval(positive.params))
        trueResult = Request.queryPage(payload, place)

        if trueResult:
            infoMsg  = "confirming %s (%s) injection " % (case.desc, logic)
            infoMsg += "on %s parameter '%s'" % (place, parameter)
            logger.info(infoMsg)

            payload = agent.payload(place, parameter, value, negative.format % eval(negative.params))

            randInt = randomInt()
            randStr = randomStr()

            falseResult = Request.queryPage(payload, place)

            if not falseResult:
                infoMsg  = "%s parameter '%s' is %s (%s) injectable " % (place, parameter, case.desc, logic)
                infoMsg += "with %d parenthesis" % parenthesis
                logger.info(infoMsg)

                if conf.beep:
                    beep()

                retVal = case.name
                break

    kb.paramMatchRatio[(place, parameter)] = conf.matchRatio

    return retVal

def heuristicCheckSqlInjection(place, parameter, value):
    if kb.nullConnection:
        debugMsg  = "heuristic checking skipped "
        debugMsg += "because NULL connection used"
        logger.debug(debugMsg)
        return

    prefix = ""
    postfix = ""

    if conf.prefix or conf.postfix:
        if conf.prefix:
            prefix = conf.prefix

        if conf.postfix:
            postfix = conf.postfix

    payload = "%s%s%s%s" % (value, prefix, randomStr(length=10, alphabet=['"', '\'', ')', '(']), postfix)
    payload = agent.payload(place, parameter, value, payload)
    Request.queryPage(payload, place, raise404=False)
    result = wasLastRequestDBMSError()

    infoMsg  = "(error based) heuristics shows that %s " % place
    infoMsg += "parameter '%s' is " % parameter

    if result:
        infoMsg += "injectable (possible DBMS: %s)" % (kb.htmlFp[-1] if kb.htmlFp else 'Unknown')
        logger.info(infoMsg)
    else:
        infoMsg += "not injectable"
        logger.warning(infoMsg)

def checkDynParam(place, parameter, value):
    """
    This function checks if the url parameter is dynamic. If it is
    dynamic, the content of the page differs, otherwise the
    dynamicity might depend on another parameter.
    """

    conf.matchRatio = None

    infoMsg = "testing if %s parameter '%s' is dynamic" % (place, parameter)
    logger.info(infoMsg)

    randInt = randomInt()
    payload = agent.payload(place, parameter, value, getUnicode(randInt))
    dynResult = Request.queryPage(payload, place)

    if True == dynResult:
        return False

    infoMsg = "confirming that %s parameter '%s' is dynamic" % (place, parameter)
    logger.info(infoMsg)

    randInt = randomInt()
    payload = agent.payload(place, parameter, value, getUnicode(randInt))
    dynResult = Request.queryPage(payload, place)

    return not dynResult

def checkDynamicContent(firstPage, secondPage):
    """
    This function checks if the provided pages have dynamic content. If they
    are dynamic, proper markings will be made.
    """

    if kb.nullConnection:
        debugMsg  = "dynamic content checking skipped "
        debugMsg += "because NULL connection used"
        logger.debug(debugMsg)
        return

    if conf.longestCommon:
        debugMsg  = "dynamic content checking skipped "
        debugMsg += "because longest common comparison used"
        logger.debug(debugMsg)
        return

    infoMsg = "searching for dynamic content"
    logger.info(infoMsg)

    blocks = SequenceMatcher(None, firstPage, secondPage).get_matching_blocks()
    kb.dynamicMarkings = []

    i = 0
    while i < len(blocks):
        block = blocks[i]
        (_, _, length) = block

        if length <= conf.minMatchBlock:
            blocks.remove(block)

        else:
            i += 1

    if len(blocks) > 0:
        blocks.insert(0, None)
        blocks.append(None)

        for i in xrange(len(blocks) - 1):
            prefix = firstPage[blocks[i][0]:blocks[i][0] + blocks[i][2]] if blocks[i] else None
            postfix = firstPage[blocks[i + 1][0]:blocks[i + 1][0] + blocks[i + 1][2]] if blocks[i + 1] else None

            if prefix is None and blocks[i + 1][0] == 0:
                continue

            if postfix is None and (blocks[i][0] + blocks[i][2] >= len(firstPage)):
                continue

            kb.dynamicMarkings.append((re.escape(prefix[-conf.dynMarkLength:]) if prefix else None, re.escape(postfix[:conf.dynMarkLength]) if postfix else None))

    if len(kb.dynamicMarkings) > 0:
        infoMsg = "dynamic content marked for removal (%d region%s)" % (len(kb.dynamicMarkings), 's' if len(kb.dynamicMarkings) > 1 else '')
        logger.info(infoMsg)

        if conf.seqMatcher.a:
            for item in kb.dynamicMarkings:
                prefix, postfix = item

                if prefix is None:
                    conf.seqMatcher.a = re.sub('(?s)^.+%s' % postfix, postfix, conf.seqMatcher.a)
                elif postfix is None:
                    conf.seqMatcher.a = re.sub('(?s)%s.+$' % prefix, prefix, conf.seqMatcher.a)
                else:
                    conf.seqMatcher.a = re.sub('(?s)%s.+%s' % (prefix, postfix), '%s%s' % (prefix, postfix), conf.seqMatcher.a)

def checkStability():
    """
    This function checks if the URL content is stable requesting the
    same page two times with a small delay within each request to
    assume that it is stable.

    In case the content of the page differs when requesting
    the same page, the dynamicity might depend on other parameters,
    like for instance string matching (--string).
    """

    infoMsg = "testing if the url is stable, wait a few seconds"
    logger.info(infoMsg)

    firstPage = conf.seqMatcher.a # set inside checkConnection()
    time.sleep(1)
    secondPage, _ = Request.queryPage(content=True)

    kb.pageStable = (firstPage == secondPage)

    if kb.pageStable:
        if firstPage:
            logMsg  = "url is stable"
            logger.info(logMsg)
        else:
            errMsg  = "there was an error checking the stability of page "
            errMsg += "because of lack of content. please check the "
            errMsg += "page request results (and probable errors) by "
            errMsg += "using higher verbosity levels"
            raise sqlmapNoneDataException, errMsg

    else:
        warnMsg  = "url is not stable, sqlmap will base the page "
        warnMsg += "comparison on a sequence matcher. If no dynamic nor "
        warnMsg += "injectable parameters are detected, or in case of "
        warnMsg += "junk results, refer to user's manual paragraph "
        warnMsg += "'Page comparison' and provide a string or regular "
        warnMsg += "expression to match on"
        logger.warn(warnMsg)

        message = "how do you want to proceed? [C(ontinue)/s(tring)/r(egex)/q(uit)] "
        test = readInput(message, default="C")

        if test and test[0] in ("q", "Q"):
            raise sqlmapUserQuitException

        elif test and test[0] in ("s", "S"):
            showStaticWords(firstPage, secondPage)

            message = "please enter value for parameter 'string': "
            test = readInput(message)

            if test:
                conf.string = test

                if kb.nullConnection:
                    debugMsg  = "turning off NULL connection "
                    debugMsg += "support because of string checking"
                    logger.debug(debugMsg)

                    kb.nullConnection = None
            else:
                errMsg = "Empty value supplied"
                raise sqlmapNoneDataException, errMsg

        elif test and test[0] in ("r", "R"):
            message = "please enter value for parameter 'regex': "
            test = readInput(message)

            if test:
                conf.regex = test

                if kb.nullConnection:
                    debugMsg  = "turning off NULL connection "
                    debugMsg += "support because of regex checking"
                    logger.debug(debugMsg)

                    kb.nullConnection = None
            else:
                errMsg = "Empty value supplied"
                raise sqlmapNoneDataException, errMsg
        else:
            checkDynamicContent(firstPage, secondPage)

            if not Request.queryPage():
                errMsg = "target url is too dynamic. unable to continue. "
                errMsg += "consider using other switches (e.g. "
                errMsg += "--longest-common, --string, --text-only, etc.)"
                raise sqlmapSiteTooDynamic, errMsg

    return kb.pageStable

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

def checkNullConnection():
    """
    Reference: http://www.wisec.it/sectou.php?id=472f952d79293
    """

    infoMsg = "testing NULL connection to the target url"
    logger.info(infoMsg)

    try:
        page, headers = Request.getPage(method=HTTPMETHOD.HEAD)
        if not page and 'Content-Length' in headers:
            kb.nullConnection = NULLCONNECTION.HEAD

            infoMsg = "NULL connection is supported with HEAD header"
            logger.info(infoMsg)
        else:
            page, headers = Request.getPage(auxHeaders={"Range": "bytes=-1"})
            if page and len(page) == 1 and 'Content-Range' in headers:
                kb.nullConnection = NULLCONNECTION.RANGE

                infoMsg = "NULL connection is supported with GET header "
                infoMsg += "'%s'" % kb.nullConnection
                logger.info(infoMsg)
    except sqlmapConnectionException, errMsg:
        errMsg = getUnicode(errMsg)
        raise sqlmapConnectionException, errMsg

    return kb.nullConnection is not None

def checkConnection(suppressOutput=False):
    try:
        socket.gethostbyname(conf.hostname)
    except socket.gaierror:
        errMsg = "host '%s' does not exist" % conf.hostname
        raise sqlmapConnectionException, errMsg

    if not suppressOutput:
        infoMsg = "testing connection to the target url"
        logger.info(infoMsg)

    try:
        page, _ = Request.queryPage(content=True)
        conf.seqMatcher.set_seq1(page)

    except sqlmapConnectionException, errMsg:
        errMsg = getUnicode(errMsg)
        raise sqlmapConnectionException, errMsg

    return True
