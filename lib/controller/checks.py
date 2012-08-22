#!/usr/bin/env python

"""
Copyright (c) 2006-2012 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import httplib
import random
import re
import socket
import time

from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import beep
from lib.core.common import extractRegexResult
from lib.core.common import extractTextTagContent
from lib.core.common import findDynamicContent
from lib.core.common import Format
from lib.core.common import getComparePageRatio
from lib.core.common import getLastRequestHTTPError
from lib.core.common import getSortedInjectionTests
from lib.core.common import getUnicode
from lib.core.common import intersect
from lib.core.common import listToStrValue
from lib.core.common import parseFilePaths
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import showStaticWords
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import wasLastRequestDBMSError
from lib.core.common import wasLastRequestHTTPError
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import AttribDict
from lib.core.datatype import InjectionDict
from lib.core.enums import HTTPHEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NULLCONNECTION
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import sqlmapConnectionException
from lib.core.exception import sqlmapNoneDataException
from lib.core.exception import sqlmapSilentQuitException
from lib.core.exception import sqlmapUserQuitException
from lib.core.settings import CONSTANT_RATIO
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.core.settings import LOWER_RATIO_BOUND
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.settings import IDS_WAF_CHECK_PAYLOAD
from lib.core.threads import getCurrentThreadData
from lib.request.connect import Connect as Request
from lib.request.inject import checkBooleanExpression
from lib.request.templates import getPageTemplate
from lib.techniques.union.test import unionTest
from lib.techniques.union.use import configUnion

def checkSqlInjection(place, parameter, value):
    # Store here the details about boundaries and payload used to
    # successfully inject
    injection = InjectionDict()

    # Localized thread data needed for some methods
    threadData = getCurrentThreadData()

    # Set the flag for SQL injection test mode
    kb.testMode = True

    for test in getSortedInjectionTests():
        try:
            if kb.endDetection:
                break

            title = test.title
            stype = test.stype
            clause = test.clause
            unionExtended = False

            if stype == PAYLOAD.TECHNIQUE.UNION:
                configUnion(test.request.char)

                if "[CHAR]" in title:
                    if conf.uChar is None:
                        continue
                    else:
                        title = title.replace("[CHAR]", conf.uChar)

                elif "[RANDNUM]" in title or "(NULL)" in title:
                    title = title.replace("[RANDNUM]", "random number")

                if test.request.columns == "[COLSTART]-[COLSTOP]":
                    if conf.uCols is None:
                        continue
                    else:
                        title = title.replace("[COLSTART]", str(conf.uColsStart))
                        title = title.replace("[COLSTOP]", str(conf.uColsStop))

                elif conf.uCols is not None:
                    debugMsg = "skipping test '%s' because the user " % title
                    debugMsg += "provided custom column range %s" % conf.uCols
                    logger.debug(debugMsg)
                    continue

                match = re.search(r"(\d+)-(\d+)", test.request.columns)
                if injection.data and match:
                    lower, upper = int(match.group(1)), int(match.group(2))
                    for _ in (lower, upper):
                        if _ > 1:
                            unionExtended = True
                            test.request.columns = re.sub(r"\b%d\b" % _, str(2 * _), test.request.columns)
                            title = re.sub(r"\b%d\b" % _, str(2 * _), title)
                            test.title = re.sub(r"\b%d\b" % _, str(2 * _), test.title)

            # Skip test if the user's wants to test only for a specific
            # technique
            if conf.tech and isinstance(conf.tech, list) and stype not in conf.tech:
                debugMsg = "skipping test '%s' because the user " % title
                debugMsg += "specified to test only for "
                debugMsg += "%s techniques" % " & ".join(map(lambda x: PAYLOAD.SQLINJECTION[x], conf.tech))
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

            # Skip tests if title is not included by the given filter
            if conf.testFilter:
                if not any(re.search(conf.testFilter, str(item), re.I) for item in (test.title, test.vector,\
                test.details.dbms if "details" in test and "dbms" in test.details else "")):
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "its name/vector/dbms is not included by the given filter"
                    logger.debug(debugMsg)
                    continue
            else:
                # Skip test if the risk is higher than the provided (or default)
                # value
                # Parse test's <risk>
                if test.risk > conf.risk:
                    debugMsg = "skipping test '%s' because the risk (%d) " % (title, test.risk)
                    debugMsg += "is higher than the provided (%d)" % conf.risk
                    logger.debug(debugMsg)
                    continue

                # Skip test if the level is higher than the provided (or default)
                # value
                # Parse test's <level>
                if test.level > conf.level:
                    debugMsg = "skipping test '%s' because the level (%d) " % (title, test.level)
                    debugMsg += "is higher than the provided (%d)" % conf.level
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
                if injection.dbms is not None and not intersect(injection.dbms, dbms):
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "the back-end DBMS identified is "
                    debugMsg += "%s" % injection.dbms
                    logger.debug(debugMsg)
                    continue

                if conf.dbms is not None and not intersect(conf.dbms.lower(), [value.lower() for value in arrayizeValue(dbms)]):
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "the provided DBMS is %s" % conf.dbms
                    logger.debug(debugMsg)
                    continue

                if len(Backend.getErrorParsedDBMSes()) > 0 and not intersect(dbms, Backend.getErrorParsedDBMSes()) and kb.skipOthersDbms is None:
                    msg = "parsed error message(s) showed that the "
                    msg += "back-end DBMS could be %s. " % Format.getErrorParsedDBMSes()
                    msg += "Do you want to skip test payloads specific for other DBMSes? [Y/n]"

                    if readInput(msg, default="Y") in ("y", "Y"):
                        kb.skipOthersDbms = Backend.getErrorParsedDBMSes()
                    else:
                        kb.skipOthersDbms = []

                if kb.skipOthersDbms and not intersect(dbms, kb.skipOthersDbms):
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "the parsed error message(s) showed "
                    debugMsg += "that the back-end DBMS could be "
                    debugMsg += "%s" % Format.getErrorParsedDBMSes()
                    logger.debug(debugMsg)
                    continue

            # Skip test if it does not match the same SQL injection clause
            # already identified by another test
            clauseMatch = False

            for clauseTest in clause:
                if injection.clause is not None and clauseTest in injection.clause:
                    clauseMatch = True
                    break

            if clause != [0] and injection.clause and injection.clause != [0] and not clauseMatch:
                debugMsg = "skipping test '%s' because the clauses " % title
                debugMsg += "differs from the clause already identified"
                logger.debug(debugMsg)
                continue

            # Skip test if the user provided custom character
            if conf.uChar is not None and ("random number" in title or "(NULL)" in title):
                debugMsg = "skipping test '%s' because the user " % title
                debugMsg += "provided a specific character, %s" % conf.uChar
                logger.debug(debugMsg)
                continue

            infoMsg = "testing '%s'" % title
            logger.info(infoMsg)

            # Force back-end DBMS according to the current
            # test value for proper payload unescaping
            Backend.forceDbms(dbms[0] if isinstance(dbms, list) else dbms)

            # Parse test's <request>
            comment = agent.getComment(test.request) if len(conf.boundaries) > 1 else None
            fstPayload = agent.cleanupPayload(test.request.payload, origValue=value)

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

                if test.clause != [0] and boundary.clause != [0] and not clauseMatch:
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
                    if where == PAYLOAD.WHERE.ORIGINAL:
                        origValue = value
                    elif where == PAYLOAD.WHERE.NEGATIVE:
                        # Use different page template than the original
                        # one as we are changing parameters value, which
                        # will likely result in a different content
                        if conf.invalidLogical:
                            origValue = "%s AND %s=%s" % (origValue, randomInt(), randomInt())
                        elif conf.invalidBignum:
                            origValue = "%d.%d" % (randomInt(6), randomInt(1))
                        else:
                            origValue = "-%s" % randomInt()
                        templatePayload = agent.payload(place, parameter, newValue=origValue, where=where)
                    elif where == PAYLOAD.WHERE.REPLACE:
                        origValue = ""

                    kb.pageTemplate, kb.errorIsNone = getPageTemplate(templatePayload, place)

                    # Forge request payload by prepending with boundary's
                    # prefix and appending the boundary's suffix to the
                    # test's ' <payload><comment> ' string
                    boundPayload = agent.prefixQuery(fstPayload, prefix, where, clause)
                    boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                    reqPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)

                    # Perform the test's request and check whether or not the
                    # payload was successful
                    # Parse test's <response>
                    for method, check in test.response.items():
                        check = agent.cleanupPayload(check, origValue=value)

                        # In case of boolean-based blind SQL injection
                        if method == PAYLOAD.METHOD.COMPARISON:
                            # Generate payload used for comparison
                            def genCmpPayload():
                                sndPayload = agent.cleanupPayload(test.response.comparison, origValue=value)

                                # Forge response payload by prepending with
                                # boundary's prefix and appending the boundary's
                                # suffix to the test's ' <payload><comment> '
                                # string
                                boundPayload = agent.prefixQuery(sndPayload, prefix, where, clause)
                                boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                                cmpPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)

                                return cmpPayload

                            # Useful to set kb.matchRatio at first based on
                            # the False response content
                            kb.matchRatio = None
                            kb.negativeLogic = (where == PAYLOAD.WHERE.NEGATIVE)
                            Request.queryPage(genCmpPayload(), place, raise404=False)
                            falsePage = threadData.lastComparisonPage or ""

                            # Perform the test's True request
                            trueResult = Request.queryPage(reqPayload, place, raise404=False)
                            truePage = threadData.lastComparisonPage or ""

                            if trueResult:
                                falseResult = Request.queryPage(genCmpPayload(), place, raise404=False)

                                # Perform the test's False request
                                if not falseResult:
                                    infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                    logger.info(infoMsg)

                                    injectable = True

                            if not injectable and not any((conf.string, conf.notString, conf.regexp)) and kb.pageStable:
                                trueSet = set(extractTextTagContent(truePage))
                                falseSet = set(extractTextTagContent(falsePage))
                                candidates = filter(None, (_.strip() if _.strip() in (kb.pageTemplate or "") and _.strip() not in falsePage else None for _ in (trueSet - falseSet)))
                                if candidates:
                                    conf.string = random.sample(candidates, 1)[0]
                                    infoMsg = "%s parameter '%s' seems to be '%s' injectable (with --string=\"%s\")" % (place, parameter, title, repr(conf.string).lstrip('u').strip("'"))
                                    logger.info(infoMsg)

                                    injectable = True

                        # In case of error-based SQL injection
                        elif method == PAYLOAD.METHOD.GREP:
                            # Perform the test's request and grep the response
                            # body for the test's <grep> regular expression
                            try:
                                page, headers = Request.queryPage(reqPayload, place, content=True, raise404=False)
                                output = extractRegexResult(check, page, re.DOTALL | re.IGNORECASE) \
                                        or extractRegexResult(check, listToStrValue(headers.headers \
                                        if headers else None), re.DOTALL | re.IGNORECASE) \
                                        or extractRegexResult(check, threadData.lastRedirectMsg[1] \
                                        if threadData.lastRedirectMsg and threadData.lastRedirectMsg[0] == \
                                        threadData.lastRequestUID else None, re.DOTALL | re.IGNORECASE)

                                if output:
                                    result = output == "1"

                                    if result:
                                        infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                        logger.info(infoMsg)

                                        injectable = True

                            except sqlmapConnectionException, msg:
                                debugMsg = "problem occured most likely because the "
                                debugMsg += "server hasn't recovered as expected from the "
                                debugMsg += "error-based payload used ('%s')" % msg
                                logger.debug(debugMsg)

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

                            configUnion(test.request.char, test.request.columns)

                            if not Backend.getIdentifiedDbms():
                                warnMsg = "using unescaped version of the test "
                                warnMsg += "because of zero knowledge of the "
                                warnMsg += "back-end DBMS. You can try to "
                                warnMsg += "explicitly set it using the --dbms "
                                warnMsg += "option"
                                singleTimeWarnMessage(warnMsg)

                            if unionExtended:
                                infoMsg = "automatically extending ranges "
                                infoMsg += "for UNION query injection technique tests as "
                                infoMsg += "there is at least one other potential "
                                infoMsg += "injection technique found"
                                singleTimeLogMessage(infoMsg)

                            # Test for UNION query SQL injection
                            reqPayload, vector = unionTest(comment, place, parameter, value, prefix, suffix)

                            if isinstance(reqPayload, basestring):
                                infoMsg = "%s parameter '%s' is '%s' injectable" % (place, parameter, title)
                                logger.info(infoMsg)

                                injectable = True

                                # Overwrite 'where' because it can be set
                                # by unionTest() directly
                                where = vector[6]

                        kb.previousMethod = method

                    # If the injection test was successful feed the injection
                    # object with the test's details
                    if injectable is True:
                        # Feed with the boundaries details only the first time a
                        # test has been successful
                        if injection.place is None or injection.parameter is None:
                            if place in (PLACE.USER_AGENT, PLACE.REFERER, PLACE.HOST):
                                injection.parameter = place
                            else:
                                injection.parameter = parameter

                            injection.place = place
                            injection.ptype = ptype
                            injection.prefix = prefix
                            injection.suffix = suffix
                            injection.clause = clause

                        # Feed with test details every time a test is successful
                        if hasattr(test, "details"):
                            for dKey, dValue in test.details.items():
                                if dKey == "dbms":
                                    if not isinstance(dValue, list):
                                        injection.dbms = Backend.setDbms(dValue)
                                    else:
                                        Backend.forceDbms(dValue[0], True)
                                elif dKey == "dbms_version" and injection.dbms_version is None and not conf.testFilter:
                                    injection.dbms_version = Backend.setVersion(dValue)
                                elif dKey == "os" and injection.os is None:
                                    injection.os = Backend.setOs(dValue)

                        if vector is None and "vector" in test and test.vector is not None:
                            vector = "%s%s" % (test.vector, comment or "")

                        injection.data[stype] = AttribDict()
                        injection.data[stype].title = title
                        injection.data[stype].payload = agent.removePayloadDelimiters(reqPayload)
                        injection.data[stype].where = where
                        injection.data[stype].vector = vector
                        injection.data[stype].comment = comment
                        injection.data[stype].templatePayload = templatePayload
                        injection.data[stype].matchRatio = kb.matchRatio

                        injection.conf.textOnly = conf.textOnly
                        injection.conf.titles = conf.titles
                        injection.conf.string = conf.string
                        injection.conf.notString = conf.notString
                        injection.conf.regexp = conf.regexp
                        injection.conf.optimize = conf.optimize

                        if conf.beep:
                            beep()

                        # There is no need to perform this test for other
                        # <where> tags
                        break

                if injectable is True:
                    # There is no need to perform this test with others
                    # boundaries
                    break

            # Reset forced back-end DBMS value
            Backend.flushForcedDbms()

        except KeyboardInterrupt:
            warnMsg = "user aborted during detection phase"
            logger.warn(warnMsg)

            message = "How do you want to proceed? [(S)kip current test/(e)nd detection phase/(n)ext parameter/(q)uit]"
            choice = readInput(message, default="S", checkBatch=False)

            if choice[0] in ("s", "S"):
                pass
            elif choice[0] in ("n", "N"):
                return None
            elif choice[0] in ("e", "E"):
                kb.endDetection = True
            elif choice[0] in ("q", "Q"):
                raise sqlmapUserQuitException

        finally:
            # Reset forced back-end DBMS value
            Backend.flushForcedDbms()

    Backend.flushForcedDbms(True)

    # Return the injection object
    if injection.place is not None and injection.parameter is not None:
        if not conf.dropSetCookie and PAYLOAD.TECHNIQUE.BOOLEAN in injection.data and injection.data[PAYLOAD.TECHNIQUE.BOOLEAN].vector.startswith('OR'):
            warnMsg = "in OR boolean-based injections, please consider usage "
            warnMsg += "of switch '--drop-set-cookie' if you experience any "
            warnMsg += "problems during data retrieval"
            logger.warn(warnMsg)

        injection = checkFalsePositives(injection)
        return injection
    else:
        return None

def checkFalsePositives(injection):
    """
    Checks for false positives (only in single special cases)
    """

    retVal = injection

    if len(injection.data) == 1 and any(map(lambda x: x in injection.data, [PAYLOAD.TECHNIQUE.BOOLEAN, PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED]))\
      or len(injection.data) == 2 and all(map(lambda x: x in injection.data, [PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED]))\
      or len(injection.data) == 1 and 'Generic' in injection.data.values()[0].title and not Backend.getDbms():
        pushValue(kb.injection)

        infoMsg = "checking if the injection point on %s " % injection.place
        infoMsg += "parameter '%s' is a false positive" % injection.parameter
        logger.info(infoMsg)

        def _():
            return int(randomInt(2)) + 1

        kb.injection = injection
        randInt1, randInt2, randInt3 = (_() for i in xrange(3))

        # Just in case (also, they have to be different than 0 because of the last test)
        while randInt1 == randInt2:
            randInt2 = _()

        # Simple arithmetic operations which should show basic
        # arithmetic ability of the backend if it's really injectable
        if not checkBooleanExpression("(%d+%d)=%d" % (randInt1, randInt2, randInt1 + randInt2)):
            retVal = None
        elif checkBooleanExpression("%d>(%d+%d)" % (min(randInt1, randInt2), randInt3, max(randInt1, randInt2))):
            retVal = None
        elif checkBooleanExpression("(%d+%d)>%d" % (randInt3, min(randInt1, randInt2), randInt1 + randInt2 + randInt3)):
            retVal = None
        elif not checkBooleanExpression("%d=(%d+%d)" % (randInt1 + randInt2, randInt1, randInt2)):
            retVal = None

        if retVal is None:
            warnMsg = "false positive or unexploitable injection point detected"
            logger.warn(warnMsg)

        kb.injection = popValue()

    return retVal

def heuristicCheckSqlInjection(place, parameter):
    if kb.nullConnection:
        debugMsg = "heuristic checking skipped "
        debugMsg += "because NULL connection used"
        logger.debug(debugMsg)
        return None

    if wasLastRequestDBMSError():
        debugMsg = "heuristic checking skipped "
        debugMsg += "because original page content "
        debugMsg += "contains DBMS error"
        logger.debug(debugMsg)
        return None

    prefix = ""
    suffix = ""

    if conf.prefix or conf.suffix:
        if conf.prefix:
            prefix = conf.prefix

        if conf.suffix:
            suffix = conf.suffix

    payload = "%s%s%s" % (prefix, randomStr(length=10, alphabet=['"', '\'', ')', '(']), suffix)
    payload = agent.payload(place, parameter, newValue=payload)
    page, _ = Request.queryPage(payload, place, content=True, raise404=False)

    parseFilePaths(page)
    result = wasLastRequestDBMSError()

    infoMsg = "heuristic test shows that %s " % place
    infoMsg += "parameter '%s' might " % parameter

    casting = False
    if not result and kb.dynamicParameter:
        origValue = conf.paramDict[place][parameter]

        if origValue and origValue.isdigit():
            randInt = int(randomInt())
            payload = "%s%s%s" % (prefix, "%d-%d" % (int(origValue) + randInt, randInt), suffix)
            payload = agent.payload(place, parameter, newValue=payload, where=PAYLOAD.WHERE.REPLACE)
            result = Request.queryPage(payload, place, raise404=False)

            if not result:
                randStr = randomStr()
                payload = "%s%s%s" % (prefix, "%s%s" % (origValue, randStr), suffix)
                payload = agent.payload(place, parameter, newValue=payload, where=PAYLOAD.WHERE.REPLACE)
                casting = Request.queryPage(payload, place, raise404=False)

    kb.heuristicTest = result

    if result:
        infoMsg += "be injectable (possible DBMS: %s)" % (Format.getErrorParsedDBMSes() or UNKNOWN_DBMS_VERSION)
        logger.info(infoMsg)
    else:
        infoMsg += "not be injectable"
        logger.warn(infoMsg)

    if casting:
        errMsg = "possible integer casting "
        errMsg += "detected (e.g. %s=(int)$_REQUEST('%s')) " % (parameter, parameter)
        errMsg += "at the back-end web application"
        logger.error(errMsg)

        message = "do you want to skip those kind of cases? [Y/n] "
        kb.ignoreCasted = readInput(message, default='Y').upper() != 'N'

    return result

def checkDynParam(place, parameter, value):
    """
    This function checks if the url parameter is dynamic. If it is
    dynamic, the content of the page differs, otherwise the
    dynamicity might depend on another parameter.
    """

    if kb.redirectChoice:
        return None

    kb.matchRatio = None
    dynResult = None
    randInt = randomInt()

    infoMsg = "testing if %s parameter '%s' is dynamic" % (place, parameter)
    logger.info(infoMsg)

    try:
        payload = agent.payload(place, parameter, value, getUnicode(randInt))
        dynResult = Request.queryPage(payload, place, raise404=False)

        if not dynResult:
            infoMsg = "confirming that %s parameter '%s' is dynamic" % (place, parameter)
            logger.info(infoMsg)

            randInt = randomInt()
            payload = agent.payload(place, parameter, value, getUnicode(randInt))
            dynResult = Request.queryPage(payload, place, raise404=False)
    except sqlmapConnectionException:
        pass

    result = None if dynResult is None else not dynResult
    kb.dynamicParameter = result

    return result

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
                warnMsg += "Switching to '--text-only' "
                logger.warn(warnMsg)

                conf.textOnly = True
                return

            warnMsg = "target url is heavily dynamic"
            warnMsg += ", sqlmap is going to retry the request"
            logger.critical(warnMsg)

            secondPage, _ = Request.queryPage(content=True)
            findDynamicContent(firstPage, secondPage)

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

    firstPage = kb.originalPage  # set inside checkConnection()
    time.sleep(1)
    secondPage, _ = Request.queryPage(content=True, raise404=False)

    if kb.redirectChoice:
        return None

    kb.pageStable = (firstPage == secondPage)

    if kb.pageStable:
        if firstPage:
            infoMsg = "url is stable"
            logger.info(infoMsg)
        else:
            errMsg = "there was an error checking the stability of page "
            errMsg += "because of lack of content. Please check the "
            errMsg += "page request results (and probable errors) by "
            errMsg += "using higher verbosity levels"
            logger.error(errMsg)

    else:
        warnMsg = "url is not stable, sqlmap will base the page "
        warnMsg += "comparison on a sequence matcher. If no dynamic nor "
        warnMsg += "injectable parameters are detected, or in case of "
        warnMsg += "junk results, refer to user's manual paragraph "
        warnMsg += "'Page comparison' and provide a string or regular "
        warnMsg += "expression to match on"
        logger.warn(warnMsg)

        message = "how do you want to proceed? [(C)ontinue/(s)tring/(r)egex/(q)uit] "
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

    page, headers = Request.queryPage(content=True)
    rawResponse = "%s%s" % (listToStrValue(headers.headers if headers else ""), page)

    if conf.string not in rawResponse:
        warnMsg = "you provided '%s' as the string to " % conf.string
        warnMsg += "match, but such a string is not within the target "
        warnMsg += "URL raw response, sqlmap will carry on anyway"
        logger.warn(warnMsg)

    return True

def checkRegexp():
    if not conf.regexp:
        return True

    infoMsg = "testing if the provided regular expression matches within "
    infoMsg += "the target URL page content"
    logger.info(infoMsg)

    page, headers = Request.queryPage(content=True)
    rawResponse = "%s%s" % (listToStrValue(headers.headers if headers else ""), page)

    if not re.search(conf.regexp, rawResponse, re.I | re.M):
        warnMsg = "you provided '%s' as the regular expression to " % conf.regexp
        warnMsg += "match, but such a regular expression does not have any "
        warnMsg += "match within the target URL raw response, sqlmap "
        warnMsg += "will carry on anyway"
        logger.warn(warnMsg)

    return True

def checkWaf():
    """
    Reference: http://seclists.org/nmap-dev/2011/q2/att-1005/http-waf-detect.nse
    """

    if not conf.checkWaf:
        return False

    infoMsg = "testing if the target is protected by "
    infoMsg += "some kind of WAF/IPS/IDS"
    logger.info(infoMsg)

    retVal = False

    backup = dict(conf.parameters)

    conf.parameters = dict(backup)
    conf.parameters[PLACE.GET] = "" if not conf.parameters.get(PLACE.GET) else conf.parameters[PLACE.GET] + "&"
    conf.parameters[PLACE.GET] += "%s=%d %s" % (randomStr(), randomInt(), IDS_WAF_CHECK_PAYLOAD)

    kb.matchRatio = None
    Request.queryPage()

    if kb.errorIsNone and kb.matchRatio is None:
        kb.matchRatio = LOWER_RATIO_BOUND

    conf.parameters = dict(backup)
    conf.parameters[PLACE.GET] = "" if not conf.parameters.get(PLACE.GET) else conf.parameters[PLACE.GET] + "&"
    conf.parameters[PLACE.GET] += "%s=%d" % (randomStr(), randomInt())

    trueResult = Request.queryPage()

    if trueResult:
        conf.parameters = dict(backup)
        conf.parameters[PLACE.GET] = "" if not conf.parameters.get(PLACE.GET) else conf.parameters[PLACE.GET] + "&"
        conf.parameters[PLACE.GET] += "%s=%d %s" % (randomStr(), randomInt(), IDS_WAF_CHECK_PAYLOAD)

        falseResult = Request.queryPage()

        if not falseResult:
            retVal = True

    conf.parameters = dict(backup)

    if retVal:
        warnMsg = "it appears that the target is protected. Please "
        warnMsg += "consider usage of tamper scripts (option '--tamper')"
        logger.warn(warnMsg)
    else:
        infoMsg = "it appears that the target is not protected"
        logger.info(infoMsg)

    return retVal

def checkNullConnection():
    """
    Reference: http://www.wisec.it/sectou.php?id=472f952d79293
    """

    if conf.data:
        return False

    infoMsg = "testing NULL connection to the target url"
    logger.info(infoMsg)

    try:
        page, headers, _ = Request.getPage(method=HTTPMETHOD.HEAD)

        if not page and HTTPHEADER.CONTENT_LENGTH in headers:
            kb.nullConnection = NULLCONNECTION.HEAD

            infoMsg = "NULL connection is supported with HEAD header"
            logger.info(infoMsg)
        else:
            page, headers, _ = Request.getPage(auxHeaders={HTTPHEADER.RANGE: "bytes=-1"})

            if page and len(page) == 1 and HTTPHEADER.CONTENT_RANGE in headers:
                kb.nullConnection = NULLCONNECTION.RANGE

                infoMsg = "NULL connection is supported with GET header "
                infoMsg += "'%s'" % kb.nullConnection
                logger.info(infoMsg)

    except sqlmapConnectionException, errMsg:
        errMsg = getUnicode(errMsg)
        raise sqlmapConnectionException, errMsg

    return kb.nullConnection is not None

def checkConnection(suppressOutput=False):
    if not any([conf.proxy, conf.tor]):
        try:
            socket.getaddrinfo(conf.hostname, None)
        except socket.gaierror:
            errMsg = "host '%s' does not exist" % conf.hostname
            raise sqlmapConnectionException, errMsg

    if not suppressOutput:
        infoMsg = "testing connection to the target url"
        logger.info(infoMsg)

    try:
        page, _ = Request.queryPage(content=True, noteResponseTime=False)
        kb.originalPage = kb.pageTemplate = page

        kb.errorIsNone = False

        if not kb.originalPage and wasLastRequestHTTPError():
            errMsg = "unable to retrieve page content"
            raise sqlmapConnectionException, errMsg
        elif wasLastRequestDBMSError():
            warnMsg = "there is a DBMS error found in the HTTP response body "
            warnMsg += "which could interfere with the results of the tests"
            logger.warn(warnMsg)
        elif wasLastRequestHTTPError():
            warnMsg = "the web server responded with an HTTP error code (%d) " % getLastRequestHTTPError()
            warnMsg += "which could interfere with the results of the tests"
            logger.warn(warnMsg)
        else:
            kb.errorIsNone = True

    except sqlmapConnectionException, errMsg:
        errMsg = getUnicode(errMsg)
        logger.critical(errMsg)

        if conf.ipv6:
            warnMsg = "check connection to a provided "
            warnMsg += "IPv6 address with a tool like ping6 "
            warnMsg += "(e.g. 'ping6 %s') " % conf.hostname
            warnMsg += "prior to running sqlmap to avoid "
            warnMsg += "any addressing issues"
            singleTimeWarnMessage(warnMsg)

        if any(code in kb.httpErrorCodes for code in (httplib.NOT_FOUND, )):
            if conf.multipleTargets:
                return False

            msg = "it is not recommended to continue in this kind of cases. Do you want to quit and make sure that everything is set up properly? [Y/n] "
            if readInput(msg, default="Y") not in ("n", "N"):
                raise sqlmapSilentQuitException
            else:
                kb.ignoreNotFound = True
        else:
            raise

    return True
