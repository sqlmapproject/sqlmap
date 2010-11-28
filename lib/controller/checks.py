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
from lib.core.common import calculateDeltaSeconds
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
from lib.core.datatype import advancedDict
from lib.core.datatype import injectionDict
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NULLCONNECTION
from lib.core.enums import PAYLOAD
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapGenericException
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapSiteTooDynamic
from lib.core.exception import sqlmapUserQuitException
from lib.core.session import setString
from lib.core.session import setRegexp
from lib.core.settings import ERROR_SPACE
from lib.core.settings import ERROR_EMPTY_CHAR
from lib.request.connect import Connect as Request
from plugins.dbms.firebird.syntax import Syntax as Firebird
from plugins.dbms.postgresql.syntax import Syntax as PostgreSQL
from plugins.dbms.mssqlserver.syntax import Syntax as MSSQLServer
from plugins.dbms.oracle.syntax import Syntax as Oracle
from plugins.dbms.mysql.syntax import Syntax as MySQL
from plugins.dbms.access.syntax import Syntax as Access
from plugins.dbms.sybase.syntax import Syntax as Sybase
from plugins.dbms.sqlite.syntax import Syntax as SQLite
from plugins.dbms.maxdb.syntax import Syntax as MaxDB


def unescape(string, dbms):
    unescaper = {
                  "Access": Access.unescape,
                  "Firebird": Firebird.unescape,
                  "MaxDB": MaxDB.unescape,
                  "Microsoft SQL Server": MSSQLServer.unescape,
                  "MySQL": MySQL.unescape,
                  "Oracle": Oracle.unescape,
                  "PostgreSQL": PostgreSQL.unescape,
                  "SQLite": SQLite.unescape,
                  "Sybase": Sybase.unescape
                }

    return unescaper[dbms](string)

def checkSqlInjection(place, parameter, value):
    # Store here the details about boundaries and payload used to
    # successfully inject
    injection = injectionDict()

    for test in conf.tests:
        title = test.title
        stype = test.stype
        proceed = True

        # Parse test's <risk>
        if test.risk > conf.risk:
            debugMsg = "skipping test '%s' because the risk " % title
            debugMsg += "is higher than the provided"
            logger.debug(debugMsg)
            continue

        # Parse test's <level>
        if test.level > conf.level:
            debugMsg = "skipping test '%s' because the level " % title
            debugMsg += "is higher than the provided"
            logger.debug(debugMsg)
            continue

        if "details" in test and "dbms" in test.details:
            dbms = test.details.dbms
        else:
            dbms = None

        # Skip current test if it is the same SQL injection type
        # already identified by another test
        if injection.data and stype in injection.data:
            debugMsg = "skipping test '%s' because " % title
            debugMsg += "we have already the payload for %s" % PAYLOAD.SQLINJECTION[stype]
            logger.debug(debugMsg)

            continue

        # Skip DBMS-specific tests if they do not match the DBMS
        # identified
        if injection.dbms is not None and injection.dbms != dbms:
            debugMsg = "skipping test '%s' because " % title
            debugMsg += "the back-end DBMS is %s" % injection.dbms
            logger.debug(debugMsg)

            continue

        infoMsg = "testing '%s'" % title
        logger.info(infoMsg)

        # Parse test's <request>
        payload = agent.cleanupPayload(test.request.payload)

        if dbms:
            payload = unescape(payload, dbms)

        if "comment" in test.request:
            comment = test.request.comment
        else:
            comment = ""
        testPayload = "%s%s" % (payload, comment)

        if conf.prefix is not None and conf.suffix is not None:
            boundary = advancedDict()

            boundary.level = 1
            boundary.clause = [ 0 ]
            boundary.where = [ 1, 2, 3 ]
            # TODO: inspect the conf.prefix and conf.suffix to set
            # proper ptype
            boundary.ptype = 1
            boundary.prefix = conf.prefix
            boundary.suffix = conf.suffix

            conf.boundaries.insert(0, boundary)

        for boundary in conf.boundaries:
            # Parse boundary's <level>
            if boundary.level > conf.level:
                # NOTE: shall we report every single skipped boundary too?
                continue

            # Parse test's <clause> and boundary's <clause>
            # Skip boundary if it does not match against test's <clause>
            clauseMatch = False

            for clauseTest in test.clause:
                if clauseTest in boundary.clause:
                    clauseMatch = True
                    break

            if test.clause != [ 0 ] and boundary.clause != [ 0 ] and not clauseMatch:
                continue

            # Parse test's <where> and boundary's <where>
            # Skip boundary if it does not match against test's <where>
            whereMatch = False

            for where in test.where:
                if where in boundary.where:
                    whereMatch = True
                    break

            if not whereMatch:
                continue

            # Parse boundary's <prefix>, <suffix> and <ptype>
            prefix = boundary.prefix if boundary.prefix else ""
            suffix = boundary.suffix if boundary.suffix else ""
            ptype = boundary.ptype
            injectable = False

            # If the previous injections succeeded, we know which prefix,
            # postfix and parameter type to use for further tests, no
            # need to cycle through all of the boundaries anymore
            condBound = (injection.prefix is not None and injection.suffix is not None)
            condBound &= (injection.prefix != prefix or injection.suffix != suffix)
            condType = injection.ptype is not None and injection.ptype != ptype

            if condBound or condType:
                continue

            # For each test's <where>
            for where in test.where:
                # The <where> tag defines where to add our injection
                # string to the parameter under assessment.
                if where == 1:
                    origValue = value
                elif where == 2:
                    origValue = "-%s" % value
                elif where == 3:
                    origValue = ""

                # Forge payload by prepending with boundary's prefix and
                # appending with boundary's suffix the test's
                # ' <payload><command> ' string
                boundPayload = "%s%s %s %s" % (origValue, prefix, testPayload, suffix)
                boundPayload = boundPayload.strip()
                boundPayload = agent.cleanupPayload(boundPayload)
                reqPayload = agent.payload(place, parameter, value, boundPayload)

                # Parse test's <response>
                # Check wheather or not the payload was successful
                for method, check in test.response.items():
                    check = agent.cleanupPayload(check)

                    # In case of boolean-based blind SQL injection
                    if method == "comparison":
                        sndPayload = agent.cleanupPayload(test.response.comparison)

                        if dbms:
                            sndPayload = unescape(sndPayload, dbms)

                        if "comment" in test.response:
                            sndComment = test.response.comment
                        else:
                            sndComment = ""

                        sndPayload = "%s%s" % (sndPayload, sndComment)
                        boundPayload = "%s%s %s %s" % (origValue, prefix, sndPayload, suffix)
                        boundPayload = boundPayload.strip()
                        boundPayload = agent.cleanupPayload(boundPayload)
                        cmpPayload = agent.payload(place, parameter, value, boundPayload)

                        # Useful to set conf.matchRatio at first
                        conf.matchRatio = None
                        _ = Request.queryPage(cmpPayload, place)

                        trueResult = Request.queryPage(reqPayload, place)

                        if trueResult:
                            falseResult = Request.queryPage(cmpPayload, place)

                            if not falseResult:
                                infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                logger.info(infoMsg)

                                kb.paramMatchRatio[(place, parameter)] = conf.matchRatio
                                injectable = True

                        kb.paramMatchRatio[(place, parameter)] = conf.matchRatio

                    # In case of error-based or UNION query SQL injections
                    elif method == "grep":
                        reqBody, _ = Request.queryPage(reqPayload, place, content=True)
                        match = re.search(check, reqBody, re.DOTALL | re.IGNORECASE)

                        if not match:
                            continue

                        output = match.group('result')

                        if output:
                            output = output.replace(ERROR_SPACE, " ").replace(ERROR_EMPTY_CHAR, "")

                        if output == "1":
                            infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                            logger.info(infoMsg)

                            injectable = True

                    # In case of time-based blind or stacked queries SQL injections
                    elif method == "time":
                        start = time.time()
                        _ = Request.queryPage(reqPayload, place)
                        duration = calculateDeltaSeconds(start)

                        if duration >= conf.timeSec:
                            infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                            logger.info(infoMsg)

                            injectable = True

            if injectable is True:
                injection.place = place
                injection.parameter = parameter
                injection.ptype = ptype
                injection.prefix = prefix
                injection.suffix = suffix

                injection.data[stype] = (title, where, comment, boundPayload)

                if "details" in test:
                    for detailKey, detailValue in test.details.items():
                        if detailKey == "dbms" and injection.dbms is None:
                            injection.dbms = detailValue
                        elif detailKey == "dbms_version" and injection.dbms_version is None:
                            injection.dbms_version = detailValue
                        elif detailKey == "os" and injection.os is None:
                            injection.os = detailValue

                break

    if injection.place is not None and injection.parameter is not None:
        return injection
    else:
        return None

def heuristicCheckSqlInjection(place, parameter, value):
    if kb.nullConnection:
        debugMsg  = "heuristic checking skipped "
        debugMsg += "because NULL connection used"
        logger.debug(debugMsg)
        return

    prefix = ""
    suffix = ""

    if conf.prefix or conf.suffix:
        if conf.prefix:
            prefix = conf.prefix

        if conf.suffix:
            suffix = conf.suffix

    payload = "%s%s%s%s" % (value, prefix, randomStr(length=10, alphabet=['"', '\'', ')', '(']), suffix)
    payload = agent.payload(place, parameter, value, payload)
    Request.queryPage(payload, place, raise404=False)
    result = wasLastRequestDBMSError()

    infoMsg  = "heuristics shows that %s " % place
    infoMsg += "parameter '%s' might " % parameter

    if result:
        infoMsg += "be injectable (possible DBMS: %s)" % (kb.htmlFp[-1] if kb.htmlFp else 'Unknown')
        logger.info(infoMsg)
    else:
        infoMsg += "not be injectable"
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
            suffix = firstPage[blocks[i + 1][0]:blocks[i + 1][0] + blocks[i + 1][2]] if blocks[i + 1] else None

            if prefix is None and blocks[i + 1][0] == 0:
                continue

            if suffix is None and (blocks[i][0] + blocks[i][2] >= len(firstPage)):
                continue

            kb.dynamicMarkings.append((re.escape(prefix[-conf.dynMarkLength:]) if prefix else None, re.escape(suffix[:conf.dynMarkLength]) if suffix else None))

    if len(kb.dynamicMarkings) > 0:
        infoMsg = "dynamic content marked for removal (%d region%s)" % (len(kb.dynamicMarkings), 's' if len(kb.dynamicMarkings) > 1 else '')
        logger.info(infoMsg)

        if conf.seqMatcher.a:
            for item in kb.dynamicMarkings:
                prefix, suffix = item

                if prefix is None:
                    conf.seqMatcher.a = re.sub('(?s)^.+%s' % suffix, suffix, conf.seqMatcher.a)
                elif suffix is None:
                    conf.seqMatcher.a = re.sub('(?s)%s.+$' % prefix, prefix, conf.seqMatcher.a)
                else:
                    conf.seqMatcher.a = re.sub('(?s)%s.+%s' % (prefix, suffix), '%s%s' % (prefix, suffix), conf.seqMatcher.a)

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
    else:
        warnMsg  = "you provided '%s' as the string to " % conf.string
        warnMsg += "match, but such a string is not within the target "
        warnMsg += "URL page content original request, sqlmap will "
        warnMsg += "keep going anyway"
        logger.warn(warnMsg)

    return True

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
    else:
        warnMsg  = "you provided '%s' as the regular expression to " % conf.regexp
        warnMsg += "match, but such a regular expression does not have any "
        warnMsg += "match within the target URL page content, sqlmap "
        warnMsg += "will keep going anyway"
        logger.warn(warnMsg)

    return True

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
