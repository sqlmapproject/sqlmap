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
from lib.core.common import extractRegexResult
from lib.core.common import getUnicode
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import removeDynamicContent
from lib.core.common import showStaticWords
from lib.core.common import trimAlphaNum
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
from lib.core.enums import PLACE
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapGenericException
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapSiteTooDynamic
from lib.core.exception import sqlmapUserQuitException
from lib.core.session import setString
from lib.core.session import setRegexp
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.request.templates import getPageTemplate

def unescape(string, dbms):
    if dbms in unescaper and "WAITFOR DELAY " not in string:
        return unescaper[dbms](string)
    else:
        return string

def unescapeDbms(payload, injection, dbms):
    # If this is a DBMS-specific test (dbms), sqlmap identified the
    # DBMS during previous a test (injection.dbms) or the user
    # provided a DBMS (conf.dbms), unescape the strings between single
    # quotes in the payload
    if injection.dbms is not None:
        payload = unescape(payload, injection.dbms)
    elif dbms is not None:
        payload = unescape(payload, dbms)
    elif conf.dbms is not None:
        payload = unescape(payload, conf.dbms)

    return payload

def checkSqlInjection(place, parameter, value):
    # Store here the details about boundaries and payload used to
    # successfully inject
    injection = injectionDict()

    # Clear cookies after each query page attempt
    kb.testMode = True

    for test in conf.tests:
        try:
            title = test.title
            stype = test.stype
            clause = test.clause

            # Skip test if the user's wants to test only for a specific
            # technique
            if conf.technique and isinstance(conf.technique, int) and stype != conf.technique:
                debugMsg = "skipping test '%s' because the user " % title
                debugMsg += "specified to test only for "
                debugMsg += "%s" % PAYLOAD.SQLINJECTION[conf.technique]
                logger.debug(debugMsg)
                continue

            # Skip test if the risk is higher than the provided (or default)
            # value
            # Parse test's <risk>
            if test.risk > conf.risk:
                debugMsg = "skipping test '%s' because the risk " % title
                debugMsg += "is higher than the provided"
                logger.debug(debugMsg)
                continue

            # Skip test if the level is higher than the provided (or default)
            # value
            # Parse test's <level>
            if test.level > conf.level:
                debugMsg = "skipping test '%s' because the level " % title
                debugMsg += "is higher than the provided"
                logger.debug(debugMsg)
                continue

            # Skip DBMS-specific test if it does not match either the
            # previously identified or the user's provided DBMS
            if "details" in test and "dbms" in test.details:
                dbms = test.details.dbms
            else:
                dbms = None

            if dbms is not None:
                if injection.dbms is not None and injection.dbms != dbms:
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "the back-end DBMS identified is "
                    debugMsg += "%s" % injection.dbms
                    logger.debug(debugMsg)

                    continue

                if conf.dbms is not None and conf.dbms.lower() != dbms.lower():
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "the provided DBMS is %s" % conf.dbms
                    logger.debug(debugMsg)

                    continue

            # Skip test if it is the same SQL injection type already
            # identified by another test
            if injection.data and stype in injection.data:
                debugMsg = "skipping test '%s' because " % title
                debugMsg += "the payload for %s has " % PAYLOAD.SQLINJECTION[stype]
                debugMsg += "already been identified"
                logger.debug(debugMsg)
                continue

            # Skip test if it does not match the same SQL injection clause
            # already identified by another test
            clauseMatch = False

            for clauseTest in clause:
                if injection.clause is not None and clauseTest in injection.clause:
                    clauseMatch = True
                    break

            if clause != [ 0 ] and injection.clause and injection.clause != [ 0 ] and not clauseMatch:
                debugMsg = "skipping test '%s' because the clauses " % title
                debugMsg += "differs from the clause already identified"
                logger.debug(debugMsg)
                continue

            infoMsg = "testing '%s'" % title
            logger.info(infoMsg)

            # Parse test's <request>
            comment = agent.getComment(test.request)
            fstPayload = agent.cleanupPayload(test.request.payload, value)
            fstPayload = unescapeDbms(fstPayload, injection, dbms)
            fstPayload = "%s%s" % (fstPayload, comment)

            if stype != 4 and clause != [2, 3] and clause != [ 3 ]:
                space = " "
            else:
                space = ""

            if conf.prefix is not None and conf.suffix is not None:
                # Create a custom boundary object for user's supplied prefix
                # and suffix
                boundary = advancedDict()

                boundary.level = 1
                boundary.clause = [ 0 ]
                boundary.where = [ 1, 2, 3 ]
                boundary.prefix = conf.prefix
                boundary.suffix = conf.suffix

                if " like" in boundary.suffix.lower():
                    if "'" in boundary.suffix.lower():
                        boundary.ptype = 3
                    elif '"' in boundary.suffix.lower():
                        boundary.ptype = 5
                elif "'" in boundary.suffix:
                    boundary.ptype = 2
                elif '"' in boundary.suffix:
                    boundary.ptype = 4
                else:
                    boundary.ptype = 1

                # Prepend user's provided boundaries to all others boundaries
                conf.boundaries.insert(0, boundary)

            for boundary in conf.boundaries:
                injectable = False

                # Skip boundary if the level is higher than the provided (or
                # default) value
                # Parse boundary's <level>
                if boundary.level > conf.level:
                    # NOTE: shall we report every single skipped boundary too?
                    continue

                # Skip boundary if it does not match against test's <clause>
                # Parse test's <clause> and boundary's <clause>
                clauseMatch = False

                for clauseTest in test.clause:
                    if clauseTest in boundary.clause:
                        clauseMatch = True
                        break

                if test.clause != [ 0 ] and boundary.clause != [ 0 ] and not clauseMatch:
                    continue

                # Skip boundary if it does not match against test's <where>
                # Parse test's <where> and boundary's <where>
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

                # If the previous injections succeeded, we know which prefix,
                # suffix and parameter type to use for further tests, no
                # need to cycle through the boundaries for the following tests
                condBound = (injection.prefix is not None and injection.suffix is not None)
                condBound &= (injection.prefix != prefix or injection.suffix != suffix)
                condType = injection.ptype is not None and injection.ptype != ptype

                if condBound or condType:
                    continue

                # For each test's <where>
                for where in test.where:
                    templatePayload = None

                    # Threat the parameter original value according to the
                    # test's <where> tag
                    if where == 1:
                        origValue = value
                    elif where == 2:
                        origValue = "-%s" % randomInt()
                        # Use different page template than the original one
                        # as we are changing parameters value, which will result
                        # most definitely with a different content
                        templatePayload = agent.payload(place, parameter, value, origValue)
                    elif where == 3:
                        origValue = ""

                    kb.pageTemplate = getPageTemplate(templatePayload, place)

                    # Forge request payload by prepending with boundary's
                    # prefix and appending the boundary's suffix to the
                    # test's ' <payload><comment> ' string
                    boundPayload = "%s%s%s%s %s" % (origValue, prefix, space, fstPayload, suffix)
                    boundPayload = boundPayload.strip()
                    boundPayload = agent.cleanupPayload(boundPayload, value)
                    reqPayload = agent.payload(place, parameter, value, boundPayload)

                    # Perform the test's request and check whether or not the
                    # payload was successful
                    # Parse test's <response>
                    for method, check in test.response.items():
                        check = agent.cleanupPayload(check, value)

                        # In case of boolean-based blind SQL injection
                        if method == PAYLOAD.METHOD.COMPARISON:
                            sndPayload = agent.cleanupPayload(test.response.comparison, value)
                            sndPayload = unescapeDbms(sndPayload, injection, dbms)
                            sndPayload = "%s%s" % (sndPayload, comment)

                            # Forge response payload by prepending with
                            # boundary's prefix and appending the boundary's
                            # suffix to the test's ' <payload><comment> '
                            # string
                            boundPayload = "%s%s%s%s %s" % (origValue, prefix, space, sndPayload, suffix)
                            boundPayload = boundPayload.strip()
                            boundPayload = agent.cleanupPayload(boundPayload, value)
                            cmpPayload = agent.payload(place, parameter, value, boundPayload)

                            # Useful to set kb.matchRatio at first based on
                            # the False response content
                            kb.matchRatio = None
                            _ = Request.queryPage(cmpPayload, place)

                            # Perform the test's True request
                            trueResult = Request.queryPage(reqPayload, place)

                            if trueResult:
                                falseResult = Request.queryPage(cmpPayload, place)

                                # Perform the test's False request
                                if not falseResult:
                                    infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                    logger.info(infoMsg)

                                    injectable = True

                        # In case of error-based or UNION query SQL injections
                        elif method == PAYLOAD.METHOD.GREP:
                            # Perform the test's request and grep the response
                            # body for the test's <grep> regular expression
                            reqBody, _ = Request.queryPage(reqPayload, place, content=True)
                            output = extractRegexResult(check, reqBody, re.DOTALL | re.IGNORECASE)

                            if output:
                                result = output.replace(kb.misc.space, " ") == "1"

                                if result:
                                    infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                    logger.info(infoMsg)

                                    injectable = True

                        # In case of time-based blind or stacked queries
                        # SQL injections
                        elif method == PAYLOAD.METHOD.TIME:
                            # Perform the test's request
                            trueResult = Request.queryPage(reqPayload, place, timeBasedCompare=True)

                            if trueResult:
                                # Confirm test's results
                                trueResult = Request.queryPage(reqPayload, place, timeBasedCompare=True)

                                if trueResult:
                                    infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                    logger.info(infoMsg)

                                    injectable = True

                    # If the injection test was successful feed the injection
                    # object with the test's details
                    if injectable is True:
                        # Feed with the boundaries details only the first time a
                        # test has been successful
                        if injection.place is None or injection.parameter is None:
                            if place == PLACE.UA:
                                injection.parameter = conf.agent
                            else:
                                injection.parameter = parameter

                            injection.place = place
                            injection.ptype = ptype
                            injection.prefix = prefix
                            injection.suffix = suffix
                            injection.clause = clause

                        if "vector" in test and test.vector is not None:
                            vector = "%s%s" % (test.vector, comment)
                        else:
                            vector = None

                        # Feed with test details every time a test is successful
                        injection.data[stype] = advancedDict()
                        injection.data[stype].title = title
                        injection.data[stype].payload = agent.removePayloadDelimiters(reqPayload, False)
                        injection.data[stype].where = where
                        injection.data[stype].vector = vector
                        injection.data[stype].comment = comment
                        injection.data[stype].matchRatio = kb.matchRatio
                        injection.data[stype].templatePayload = templatePayload

                        if hasattr(test, "details"):
                            for detailKey, detailValue in test.details.items():
                                if detailKey == "dbms" and injection.dbms is None:
                                    injection.dbms = detailValue
                                    kb.dbms = detailValue
                                elif detailKey == "dbms_version" and injection.dbms_version is None:
                                    injection.dbms_version = detailValue
                                    kb.dbmsVersion = [ detailValue ]
                                elif detailKey == "os" and injection.os is None:
                                    injection.os = detailValue

                        if conf.beep or conf.scriptKiddie:
                            beep()

                        # There is no need to perform this test for other
                        # <where> tags
                        break

                if injectable is True:
                    # There is no need to perform this test with others
                    # boundaries
                    break

        except KeyboardInterrupt:
            warnMsg = "Ctrl+C detected in detection phase"
            logger.warn(warnMsg)

            message = "How do you want to proceed? [(S)kip test/(n)ext parameter/(q)uit]"
            test = readInput(message, default="S")

            if not test or test[0] in ("s", "S"):
                pass
            elif test[0] in ("n", "N"):
                break
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException

    # Flush the flag
    kb.testMode = False

    # Return the injection object
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

    infoMsg  = "heuristic test shows that %s " % place
    infoMsg += "parameter '%s' might " % parameter

    if result:
        infoMsg += "be injectable (possible DBMS: %s)" % (kb.htmlFp[-1] if kb.htmlFp else 'Unknown')
        logger.info(infoMsg)
    else:
        infoMsg += "not be injectable"
        logger.warn(infoMsg)

    return result

def checkDynParam(place, parameter, value):
    """
    This function checks if the url parameter is dynamic. If it is
    dynamic, the content of the page differs, otherwise the
    dynamicity might depend on another parameter.
    """

    kb.matchRatio = None

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

    # Removing too small matching blocks
    i = 0
    while i < len(blocks):
        block = blocks[i]
        (_, _, length) = block

        if length <= conf.dynMarkLength:
            blocks.remove(block)

        else:
            i += 1

    # Making of dynamic markings based on prefix/suffix principle
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

            prefix = trimAlphaNum(prefix)
            suffix = trimAlphaNum(suffix)

            kb.dynamicMarkings.append((re.escape(prefix[-conf.dynMarkLength/2:]) if prefix else None, re.escape(suffix[:conf.dynMarkLength/2]) if suffix else None))

    if len(kb.dynamicMarkings) > 0:
        infoMsg = "dynamic content marked for removal (%d region%s)" % (len(kb.dynamicMarkings), 's' if len(kb.dynamicMarkings) > 1 else '')
        logger.info(infoMsg)

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

    firstPage = kb.originalPage # set inside checkConnection()
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
        if not conf.scriptKiddie:
            test = readInput(message, default="C")
        else:
            test = None

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

            count = 0
            while not Request.queryPage():
                count += 1

                if count > conf.retries:
                    errMsg = "target url is too dynamic. unable to continue. "
                    errMsg += "consider using other switches (e.g. "
                    errMsg += "--longest-common, --string, --text-only, etc.)"
                    raise sqlmapSiteTooDynamic, errMsg

                warnMsg = "target url is heavily dynamic"
                warnMsg += ", sqlmap is going to retry the request"
                logger.critical(warnMsg)

                secondPage, _ = Request.queryPage(content=True)
                checkDynamicContent(firstPage, secondPage)

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
        kb.originalPage = kb.pageTemplate = page
    except sqlmapConnectionException, errMsg:
        errMsg = getUnicode(errMsg)
        raise sqlmapConnectionException, errMsg

    return True
