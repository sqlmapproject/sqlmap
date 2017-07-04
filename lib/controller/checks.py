#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import copy
import httplib
import random
import re
import socket
import subprocess
import time

from extra.beep.beep import beep
from lib.core.agent import agent
from lib.core.common import Backend
from lib.core.common import extractRegexResult
from lib.core.common import extractTextTagContent
from lib.core.common import findDynamicContent
from lib.core.common import Format
from lib.core.common import getFilteredPageContent
from lib.core.common import getLastRequestHTTPError
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import getSortedInjectionTests
from lib.core.common import getUnicode
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
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
from lib.core.common import urlencode
from lib.core.common import wasLastResponseDBMSError
from lib.core.common import wasLastResponseHTTPError
from lib.core.defaults import defaults
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import AttribDict
from lib.core.datatype import InjectionDict
from lib.core.decorators import cachedmethod
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.enums import DBMS
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NOTE
from lib.core.enums import NULLCONNECTION
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.enums import REDIRECTION
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import CANDIDATE_SENTENCE_MIN_LENGTH
from lib.core.settings import CHECK_INTERNET_ADDRESS
from lib.core.settings import CHECK_INTERNET_VALUE
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import DUMMY_NON_SQLI_CHECK_APPENDIX
from lib.core.settings import FI_ERROR_REGEX
from lib.core.settings import FORMAT_EXCEPTION_STRINGS
from lib.core.settings import HEURISTIC_CHECK_ALPHABET
from lib.core.settings import IDS_WAF_CHECK_PAYLOAD
from lib.core.settings import IDS_WAF_CHECK_RATIO
from lib.core.settings import IDS_WAF_CHECK_TIMEOUT
from lib.core.settings import MAX_DIFFLIB_SEQUENCE_LENGTH
from lib.core.settings import NON_SQLI_CHECK_PREFIX_SUFFIX_LENGTH
from lib.core.settings import SLEEP_TIME_MARKER
from lib.core.settings import SUHOSIN_MAX_VALUE_LENGTH
from lib.core.settings import SUPPORTED_DBMS
from lib.core.settings import URI_HTTP_HEADER
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.threads import getCurrentThreadData
from lib.request.connect import Connect as Request
from lib.request.comparison import comparison
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

    # Favoring non-string specific boundaries in case of digit-like parameter values
    if value.isdigit():
        kb.cache.intBoundaries = kb.cache.intBoundaries or sorted(copy.deepcopy(conf.boundaries), key=lambda boundary: any(_ in (boundary.prefix or "") or _ in (boundary.suffix or "") for _ in ('"', '\'')))
        boundaries = kb.cache.intBoundaries
    else:
        boundaries = conf.boundaries

    # Set the flag for SQL injection test mode
    kb.testMode = True

    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place
    tests = getSortedInjectionTests()
    seenPayload = set()

    kb.data.setdefault("randomInt", str(randomInt(10)))
    kb.data.setdefault("randomStr", str(randomStr(10)))

    while tests:
        test = tests.pop(0)

        try:
            if kb.endDetection:
                break

            if conf.dbms is None:
                # If the DBMS has not yet been fingerprinted (via simple heuristic check
                # or via DBMS-specific payload) and boolean-based blind has been identified
                # then attempt to identify with a simple DBMS specific boolean-based
                # test what the DBMS may be
                if not injection.dbms and PAYLOAD.TECHNIQUE.BOOLEAN in injection.data:
                    if not Backend.getIdentifiedDbms() and kb.heuristicDbms is None and not kb.droppingRequests:
                        kb.heuristicDbms = heuristicCheckDbms(injection)

                # If the DBMS has already been fingerprinted (via DBMS-specific
                # error message, simple heuristic check or via DBMS-specific
                # payload), ask the user to limit the tests to the fingerprinted
                # DBMS
                if kb.reduceTests is None and not conf.testFilter and (intersect(Backend.getErrorParsedDBMSes(), \
                   SUPPORTED_DBMS, True) or kb.heuristicDbms or injection.dbms):
                    msg = "it looks like the back-end DBMS is '%s'. " % (Format.getErrorParsedDBMSes() or kb.heuristicDbms or injection.dbms)
                    msg += "Do you want to skip test payloads specific for other DBMSes? [Y/n]"
                    kb.reduceTests = (Backend.getErrorParsedDBMSes() or [kb.heuristicDbms]) if readInput(msg, default='Y', boolean=True) else []

            # If the DBMS has been fingerprinted (via DBMS-specific error
            # message, via simple heuristic check or via DBMS-specific
            # payload), ask the user to extend the tests to all DBMS-specific,
            # regardless of --level and --risk values provided
            if kb.extendTests is None and not conf.testFilter and (conf.level < 5 or conf.risk < 3) \
               and (intersect(Backend.getErrorParsedDBMSes(), SUPPORTED_DBMS, True) or \
               kb.heuristicDbms or injection.dbms):
                msg = "for the remaining tests, do you want to include all tests "
                msg += "for '%s' extending provided " % (Format.getErrorParsedDBMSes() or kb.heuristicDbms or injection.dbms)
                msg += "level (%d)" % conf.level if conf.level < 5 else ""
                msg += " and " if conf.level < 5 and conf.risk < 3 else ""
                msg += "risk (%d)" % conf.risk if conf.risk < 3 else ""
                msg += " values? [Y/n]" if conf.level < 5 and conf.risk < 3 else " value? [Y/n]"
                kb.extendTests = (Backend.getErrorParsedDBMSes() or [kb.heuristicDbms]) if readInput(msg, default='Y', boolean=True) else []

            title = test.title
            kb.testType = stype = test.stype
            clause = test.clause
            unionExtended = False
            trueCode, falseCode = None, None

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
                            __ = 2 * (_ - 1) + 1 if _ == lower else 2 * _
                            unionExtended = True
                            test.request.columns = re.sub(r"\b%d\b" % _, str(__), test.request.columns)
                            title = re.sub(r"\b%d\b" % _, str(__), title)
                            test.title = re.sub(r"\b%d\b" % _, str(__), test.title)

            # Skip test if the user's wants to test only for a specific
            # technique
            if conf.tech and isinstance(conf.tech, list) and stype not in conf.tech:
                debugMsg = "skipping test '%s' because the user " % title
                debugMsg += "specified to test only for "
                debugMsg += "%s techniques" % " & ".join(PAYLOAD.SQLINJECTION[_] for _ in conf.tech)
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

            # Parse DBMS-specific payloads' details
            if "details" in test and "dbms" in test.details:
                payloadDbms = test.details.dbms
            else:
                payloadDbms = None

            # Skip tests if title, vector or DBMS is not included by the
            # given test filter
            if conf.testFilter and not any(conf.testFilter in str(item) or \
               re.search(conf.testFilter, str(item), re.I) for item in \
               (test.title, test.vector, payloadDbms)):
                    debugMsg = "skipping test '%s' because its " % title
                    debugMsg += "name/vector/DBMS is not included by the given filter"
                    logger.debug(debugMsg)
                    continue

            # Skip tests if title, vector or DBMS is included by the
            # given skip filter
            if conf.testSkip and any(conf.testSkip in str(item) or \
               re.search(conf.testSkip, str(item), re.I) for item in \
               (test.title, test.vector, payloadDbms)):
                    debugMsg = "skipping test '%s' because its " % title
                    debugMsg += "name/vector/DBMS is included by the given skip filter"
                    logger.debug(debugMsg)
                    continue

            if payloadDbms is not None:
                # Skip DBMS-specific test if it does not match the user's
                # provided DBMS
                if conf.dbms is not None and not intersect(payloadDbms, conf.dbms, True):
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "the provided DBMS is %s" % conf.dbms
                    logger.debug(debugMsg)
                    continue

                # Skip DBMS-specific test if it does not match the
                # previously identified DBMS (via DBMS-specific payload)
                if injection.dbms is not None and not intersect(payloadDbms, injection.dbms, True):
                    debugMsg = "skipping test '%s' because the identified " % title
                    debugMsg += "back-end DBMS is %s" % injection.dbms
                    logger.debug(debugMsg)
                    continue

                # Skip DBMS-specific test if it does not match the
                # previously identified DBMS (via DBMS-specific error message)
                if kb.reduceTests and not intersect(payloadDbms, kb.reduceTests, True):
                    debugMsg = "skipping test '%s' because the parsed " % title
                    debugMsg += "error message(s) showed that the back-end DBMS "
                    debugMsg += "could be %s" % Format.getErrorParsedDBMSes()
                    logger.debug(debugMsg)
                    continue

            # If the user did not decide to extend the tests to all
            # DBMS-specific or the test payloads is not specific to the
            # identified DBMS, then only test for it if both level and risk
            # are below the corrisponding configuration's level and risk
            # values
            if not conf.testFilter and not (kb.extendTests and intersect(payloadDbms, kb.extendTests, True)):
                # Skip test if the risk is higher than the provided (or default)
                # value
                if test.risk > conf.risk:
                    debugMsg = "skipping test '%s' because the risk (%d) " % (title, test.risk)
                    debugMsg += "is higher than the provided (%d)" % conf.risk
                    logger.debug(debugMsg)
                    continue

                # Skip test if the level is higher than the provided (or default)
                # value
                if test.level > conf.level:
                    debugMsg = "skipping test '%s' because the level (%d) " % (title, test.level)
                    debugMsg += "is higher than the provided (%d)" % conf.level
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
                debugMsg += "differ from the clause already identified"
                logger.debug(debugMsg)
                continue

            # Skip test if the user provided custom character (for UNION-based payloads)
            if conf.uChar is not None and ("random number" in title or "(NULL)" in title):
                debugMsg = "skipping test '%s' because the user " % title
                debugMsg += "provided a specific character, %s" % conf.uChar
                logger.debug(debugMsg)
                continue

            infoMsg = "testing '%s'" % title
            logger.info(infoMsg)

            # Force back-end DBMS according to the current test DBMS value
            # for proper payload unescaping
            Backend.forceDbms(payloadDbms[0] if isinstance(payloadDbms, list) else payloadDbms)

            # Parse test's <request>
            comment = agent.getComment(test.request) if len(conf.boundaries) > 1 else None
            fstPayload = agent.cleanupPayload(test.request.payload, origValue=value if place not in (PLACE.URI, PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER) else None)

            for boundary in boundaries:
                injectable = False

                # Skip boundary if the level is higher than the provided (or
                # default) value
                # Parse boundary's <level>
                if boundary.level > conf.level and not (kb.extendTests and intersect(payloadDbms, kb.extendTests, True)):
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

                # Options --prefix/--suffix have a higher priority (if set by user)
                prefix = conf.prefix if conf.prefix is not None else prefix
                suffix = conf.suffix if conf.suffix is not None else suffix
                comment = None if conf.suffix is not None else comment

                # If the previous injections succeeded, we know which prefix,
                # suffix and parameter type to use for further tests, no
                # need to cycle through the boundaries for the following tests
                condBound = (injection.prefix is not None and injection.suffix is not None)
                condBound &= (injection.prefix != prefix or injection.suffix != suffix)
                condType = injection.ptype is not None and injection.ptype != ptype

                # If the payload is an inline query test for it regardless
                # of previously identified injection types
                if stype != PAYLOAD.TECHNIQUE.QUERY and (condBound or condType):
                    continue

                # For each test's <where>
                for where in test.where:
                    templatePayload = None
                    vector = None

                    # Threat the parameter original value according to the
                    # test's <where> tag
                    if where == PAYLOAD.WHERE.ORIGINAL or conf.prefix:
                        origValue = value

                        if kb.tamperFunctions:
                            templatePayload = agent.payload(place, parameter, value="", newValue=origValue, where=where)
                    elif where == PAYLOAD.WHERE.NEGATIVE:
                        # Use different page template than the original
                        # one as we are changing parameters value, which
                        # will likely result in a different content

                        if conf.invalidLogical:
                            _ = int(kb.data.randomInt[:2])
                            origValue = "%s AND %s=%s" % (value, _, _ + 1)
                        elif conf.invalidBignum:
                            origValue = kb.data.randomInt[:6]
                        elif conf.invalidString:
                            origValue = kb.data.randomStr[:6]
                        else:
                            origValue = "-%s" % kb.data.randomInt[:4]

                        templatePayload = agent.payload(place, parameter, value="", newValue=origValue, where=where)
                    elif where == PAYLOAD.WHERE.REPLACE:
                        origValue = ""

                    kb.pageTemplate, kb.errorIsNone = getPageTemplate(templatePayload, place)

                    # Forge request payload by prepending with boundary's
                    # prefix and appending the boundary's suffix to the
                    # test's ' <payload><comment> ' string
                    if fstPayload:
                        boundPayload = agent.prefixQuery(fstPayload, prefix, where, clause)
                        boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                        reqPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)
                        if reqPayload:
                            if reqPayload in seenPayload:
                                continue
                            else:
                                seenPayload.add(reqPayload)
                    else:
                        reqPayload = None

                    # Perform the test's request and check whether or not the
                    # payload was successful
                    # Parse test's <response>
                    for method, check in test.response.items():
                        check = agent.cleanupPayload(check, origValue=value if place not in (PLACE.URI, PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER) else None)

                        # In case of boolean-based blind SQL injection
                        if method == PAYLOAD.METHOD.COMPARISON:
                            # Generate payload used for comparison
                            def genCmpPayload():
                                sndPayload = agent.cleanupPayload(test.response.comparison, origValue=value if place not in (PLACE.URI, PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER) else None)

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
                            falsePage, falseHeaders, falseCode = threadData.lastComparisonPage or "", threadData.lastComparisonHeaders, threadData.lastComparisonCode
                            falseRawResponse = "%s%s" % (falseHeaders, falsePage)

                            # Perform the test's True request
                            trueResult = Request.queryPage(reqPayload, place, raise404=False)
                            truePage, trueHeaders, trueCode = threadData.lastComparisonPage or "", threadData.lastComparisonHeaders, threadData.lastComparisonCode
                            trueRawResponse = "%s%s" % (trueHeaders, truePage)

                            if trueResult and not(truePage == falsePage and not kb.nullConnection):
                                # Perform the test's False request
                                falseResult = Request.queryPage(genCmpPayload(), place, raise404=False)

                                if not falseResult:
                                    if kb.negativeLogic:
                                        boundPayload = agent.prefixQuery(kb.data.randomStr, prefix, where, clause)
                                        boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                                        errorPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)

                                        errorResult = Request.queryPage(errorPayload, place, raise404=False)
                                        if errorResult:
                                            continue
                                    elif not any((conf.string, conf.notString, conf.regexp, conf.code, kb.nullConnection)):
                                        _ = comparison(kb.heuristicPage, None, getRatioValue=True)
                                        if _ > kb.matchRatio:
                                            kb.matchRatio = _
                                            logger.debug("adjusting match ratio for current parameter to %.3f" % kb.matchRatio)

                                    injectable = True

                                elif threadData.lastComparisonRatio > UPPER_RATIO_BOUND and not any((conf.string, conf.notString, conf.regexp, conf.code, kb.nullConnection)):
                                    originalSet = set(getFilteredPageContent(kb.pageTemplate, True, "\n").split("\n"))
                                    trueSet = set(getFilteredPageContent(truePage, True, "\n").split("\n"))
                                    falseSet = set(getFilteredPageContent(falsePage, True, "\n").split("\n"))

                                    if originalSet == trueSet != falseSet:
                                        candidates = trueSet - falseSet

                                        if candidates:
                                            candidates = sorted(candidates, key=lambda _: len(_))
                                            for candidate in candidates:
                                                if re.match(r"\A[\w.,! ]+\Z", candidate) and ' ' in candidate and candidate.strip() and len(candidate) > CANDIDATE_SENTENCE_MIN_LENGTH:
                                                    conf.string = candidate
                                                    injectable = True

                                                    infoMsg = "%s parameter '%s' appears to be '%s' injectable (with --string=\"%s\")" % (paramType, parameter, title, repr(conf.string).lstrip('u').strip("'"))
                                                    logger.info(infoMsg)

                                                    break

                            if injectable:
                                if kb.pageStable and not any((conf.string, conf.notString, conf.regexp, conf.code, kb.nullConnection)):
                                    if all((falseCode, trueCode)) and falseCode != trueCode:
                                        conf.code = trueCode

                                        infoMsg = "%s parameter '%s' appears to be '%s' injectable (with --code=%d)" % (paramType, parameter, title, conf.code)
                                        logger.info(infoMsg)
                                    else:
                                        trueSet = set(extractTextTagContent(trueRawResponse))
                                        trueSet = trueSet.union(__ for _ in trueSet for __ in _.split())

                                        falseSet = set(extractTextTagContent(falseRawResponse))
                                        falseSet = falseSet.union(__ for _ in falseSet for __ in _.split())

                                        candidates = filter(None, (_.strip() if _.strip() in trueRawResponse and _.strip() not in falseRawResponse else None for _ in (trueSet - falseSet)))

                                        if candidates:
                                            candidates = sorted(candidates, key=lambda _: len(_))
                                            for candidate in candidates:
                                                if re.match(r"\A\w+\Z", candidate):
                                                    break

                                            conf.string = candidate

                                            infoMsg = "%s parameter '%s' appears to be '%s' injectable (with --string=\"%s\")" % (paramType, parameter, title, repr(conf.string).lstrip('u').strip("'"))
                                            logger.info(infoMsg)

                                        if not any((conf.string, conf.notString)):
                                            candidates = filter(None, (_.strip() if _.strip() in falseRawResponse and _.strip() not in trueRawResponse else None for _ in (falseSet - trueSet)))

                                            if candidates:
                                                candidates = sorted(candidates, key=lambda _: len(_))
                                                for candidate in candidates:
                                                    if re.match(r"\A\w+\Z", candidate):
                                                        break

                                                conf.notString = candidate

                                                infoMsg = "%s parameter '%s' appears to be '%s' injectable (with --not-string=\"%s\")" % (paramType, parameter, title, repr(conf.notString).lstrip('u').strip("'"))
                                                logger.info(infoMsg)

                                if not any((conf.string, conf.notString, conf.code)):
                                    infoMsg = "%s parameter '%s' appears to be '%s' injectable " % (paramType, parameter, title)
                                    singleTimeLogMessage(infoMsg)

                        # In case of error-based SQL injection
                        elif method == PAYLOAD.METHOD.GREP:
                            # Perform the test's request and grep the response
                            # body for the test's <grep> regular expression
                            try:
                                page, headers, _ = Request.queryPage(reqPayload, place, content=True, raise404=False)
                                output = extractRegexResult(check, page, re.DOTALL | re.IGNORECASE) \
                                        or extractRegexResult(check, threadData.lastHTTPError[2] if wasLastResponseHTTPError() else None, re.DOTALL | re.IGNORECASE) \
                                        or extractRegexResult(check, listToStrValue([headers[key] for key in headers.keys() if key.lower() != URI_HTTP_HEADER.lower()] if headers else None), re.DOTALL | re.IGNORECASE) \
                                        or extractRegexResult(check, threadData.lastRedirectMsg[1] if threadData.lastRedirectMsg and threadData.lastRedirectMsg[0] == threadData.lastRequestUID else None, re.DOTALL | re.IGNORECASE)

                                if output:
                                    result = output == "1"

                                    if result:
                                        infoMsg = "%s parameter '%s' is '%s' injectable " % (paramType, parameter, title)
                                        logger.info(infoMsg)

                                        injectable = True

                            except SqlmapConnectionException, msg:
                                debugMsg = "problem occurred most likely because the "
                                debugMsg += "server hasn't recovered as expected from the "
                                debugMsg += "error-based payload used ('%s')" % msg
                                logger.debug(debugMsg)

                        # In case of time-based blind or stacked queries
                        # SQL injections
                        elif method == PAYLOAD.METHOD.TIME:
                            # Perform the test's request
                            trueResult = Request.queryPage(reqPayload, place, timeBasedCompare=True, raise404=False)
                            trueCode = threadData.lastCode

                            if trueResult:
                                # Extra validation step (e.g. to check for DROP protection mechanisms)
                                if SLEEP_TIME_MARKER in reqPayload:
                                    falseResult = Request.queryPage(reqPayload.replace(SLEEP_TIME_MARKER, "0"), place, timeBasedCompare=True, raise404=False)
                                    if falseResult:
                                        continue

                                # Confirm test's results
                                trueResult = Request.queryPage(reqPayload, place, timeBasedCompare=True, raise404=False)

                                if trueResult:
                                    infoMsg = "%s parameter '%s' appears to be '%s' injectable " % (paramType, parameter, title)
                                    logger.info(infoMsg)

                                    injectable = True

                        # In case of UNION query SQL injection
                        elif method == PAYLOAD.METHOD.UNION:
                            # Test for UNION injection and set the sample
                            # payload as well as the vector.
                            # NOTE: vector is set to a tuple with 6 elements,
                            # used afterwards by Agent.forgeUnionQuery()
                            # method to forge the UNION query payload

                            configUnion(test.request.char, test.request.columns)

                            if not Backend.getIdentifiedDbms():
                                if kb.heuristicDbms is None:
                                    warnMsg = "using unescaped version of the test "
                                    warnMsg += "because of zero knowledge of the "
                                    warnMsg += "back-end DBMS. You can try to "
                                    warnMsg += "explicitly set it with option '--dbms'"
                                    singleTimeWarnMessage(warnMsg)
                                else:
                                    Backend.forceDbms(kb.heuristicDbms)

                            if unionExtended:
                                infoMsg = "automatically extending ranges for UNION "
                                infoMsg += "query injection technique tests as "
                                infoMsg += "there is at least one other (potential) "
                                infoMsg += "technique found"
                                singleTimeLogMessage(infoMsg)
                            elif not injection.data:
                                _ = test.request.columns.split('-')[-1]
                                if _.isdigit() and int(_) > 10:
                                    if kb.futileUnion is None:
                                        msg = "it is not recommended to perform "
                                        msg += "extended UNION tests if there is not "
                                        msg += "at least one other (potential) "
                                        msg += "technique found. Do you want to skip? [Y/n] "

                                        kb.futileUnion = not readInput(msg, default='Y', boolean=True)
                                    if kb.futileUnion is False:
                                        continue

                            # Test for UNION query SQL injection
                            reqPayload, vector = unionTest(comment, place, parameter, value, prefix, suffix)

                            if isinstance(reqPayload, basestring):
                                infoMsg = "%s parameter '%s' is '%s' injectable" % (paramType, parameter, title)
                                logger.info(infoMsg)

                                injectable = True

                                # Overwrite 'where' because it can be set
                                # by unionTest() directly
                                where = vector[6]

                        kb.previousMethod = method

                        if conf.dummy or conf.offline:
                            injectable = False

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
                            for key, value in test.details.items():
                                if key == "dbms":
                                    injection.dbms = value

                                    if not isinstance(value, list):
                                        Backend.setDbms(value)
                                    else:
                                        Backend.forceDbms(value[0], True)

                                elif key == "dbms_version" and injection.dbms_version is None and not conf.testFilter:
                                    injection.dbms_version = Backend.setVersion(value)

                                elif key == "os" and injection.os is None:
                                    injection.os = Backend.setOs(value)

                        if vector is None and "vector" in test and test.vector is not None:
                            vector = test.vector

                        injection.data[stype] = AttribDict()
                        injection.data[stype].title = title
                        injection.data[stype].payload = agent.removePayloadDelimiters(reqPayload)
                        injection.data[stype].where = where
                        injection.data[stype].vector = vector
                        injection.data[stype].comment = comment
                        injection.data[stype].templatePayload = templatePayload
                        injection.data[stype].matchRatio = kb.matchRatio
                        injection.data[stype].trueCode = trueCode
                        injection.data[stype].falseCode = falseCode

                        injection.conf.textOnly = conf.textOnly
                        injection.conf.titles = conf.titles
                        injection.conf.code = conf.code
                        injection.conf.string = conf.string
                        injection.conf.notString = conf.notString
                        injection.conf.regexp = conf.regexp
                        injection.conf.optimize = conf.optimize

                        if not kb.alerted:
                            if conf.beep:
                                beep()

                            if conf.alert:
                                infoMsg = "executing alerting shell command(s) ('%s')" % conf.alert
                                logger.info(infoMsg)

                                process = subprocess.Popen(conf.alert, shell=True)
                                process.wait()

                            kb.alerted = True

                        # There is no need to perform this test for other
                        # <where> tags
                        break

                if injectable is True:
                    kb.vulnHosts.add(conf.hostname)
                    break

            # Reset forced back-end DBMS value
            Backend.flushForcedDbms()

        except KeyboardInterrupt:
            warnMsg = "user aborted during detection phase"
            logger.warn(warnMsg)

            msg = "how do you want to proceed? [(S)kip current test/(e)nd detection phase/(n)ext parameter/(c)hange verbosity/(q)uit]"
            choice = readInput(msg, default='S', checkBatch=False).upper()

            if choice == 'C':
                choice = None
                while not ((choice or "").isdigit() and 0 <= int(choice) <= 6):
                    if choice:
                        logger.warn("invalid value")
                    msg = "enter new verbosity level: [0-6] "
                    choice = readInput(msg, default=str(conf.verbose), checkBatch=False)
                conf.verbose = int(choice)
                setVerbosity()
                tests.insert(0, test)
            elif choice == 'N':
                return None
            elif choice == 'E':
                kb.endDetection = True
            elif choice == 'Q':
                raise SqlmapUserQuitException

        finally:
            # Reset forced back-end DBMS value
            Backend.flushForcedDbms()

    Backend.flushForcedDbms(True)

    # Return the injection object
    if injection.place is not None and injection.parameter is not None:
        if not conf.dropSetCookie and PAYLOAD.TECHNIQUE.BOOLEAN in injection.data and injection.data[PAYLOAD.TECHNIQUE.BOOLEAN].vector.startswith('OR'):
            warnMsg = "in OR boolean-based injection cases, please consider usage "
            warnMsg += "of switch '--drop-set-cookie' if you experience any "
            warnMsg += "problems during data retrieval"
            logger.warn(warnMsg)

        if not checkFalsePositives(injection):
            kb.vulnHosts.remove(conf.hostname)
            if NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE not in injection.notes:
                injection.notes.append(NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE)

    else:
        injection = None

    if injection and NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE not in injection.notes:
        checkSuhosinPatch(injection)
        checkFilteredChars(injection)

    return injection

def heuristicCheckDbms(injection):
    """
    This functions is called when boolean-based blind is identified with a
    generic payload and the DBMS has not yet been fingerprinted to attempt
    to identify with a simple DBMS specific boolean-based test what the DBMS
    may be
    """
    retVal = False

    pushValue(kb.injection)
    kb.injection = injection

    for dbms in getPublicTypeMembers(DBMS, True):
        randStr1, randStr2 = randomStr(), randomStr()
        Backend.forceDbms(dbms)

        if conf.noEscape and dbms not in FROM_DUMMY_TABLE:
            continue

        if checkBooleanExpression("(SELECT '%s'%s)='%s'" % (randStr1, FROM_DUMMY_TABLE.get(dbms, ""), randStr1)):
            if not checkBooleanExpression("(SELECT '%s'%s)='%s'" % (randStr1, FROM_DUMMY_TABLE.get(dbms, ""), randStr2)):
                retVal = dbms
                break

    Backend.flushForcedDbms()
    kb.injection = popValue()

    if retVal:
        infoMsg = "heuristic (extended) test shows that the back-end DBMS "  # Not as important as "parsing" counter-part (because of false-positives)
        infoMsg += "could be '%s' " % retVal
        logger.info(infoMsg)

        kb.heuristicExtendedDbms = retVal

    return retVal

def checkFalsePositives(injection):
    """
    Checks for false positives (only in single special cases)
    """

    retVal = True

    if all(_ in (PAYLOAD.TECHNIQUE.BOOLEAN, PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED) for _ in injection.data) or\
      (len(injection.data) == 1 and PAYLOAD.TECHNIQUE.UNION in injection.data and "Generic" in injection.data[PAYLOAD.TECHNIQUE.UNION].title):
        pushValue(kb.injection)

        infoMsg = "checking if the injection point on %s " % injection.place
        infoMsg += "parameter '%s' is a false positive" % injection.parameter
        logger.info(infoMsg)

        def _():
            return int(randomInt(2)) + 1

        kb.injection = injection

        for i in xrange(conf.level):
            while True:
                randInt1, randInt2, randInt3 = (_() for j in xrange(3))

                randInt1 = min(randInt1, randInt2, randInt3)
                randInt3 = max(randInt1, randInt2, randInt3)

                if randInt3 > randInt2 > randInt1:
                    break

            if not checkBooleanExpression("%d=%d" % (randInt1, randInt1)):
                retVal = False
                break

            # Just in case if DBMS hasn't properly recovered from previous delayed request
            if PAYLOAD.TECHNIQUE.BOOLEAN not in injection.data:
                checkBooleanExpression("%d=%d" % (randInt1, randInt2))

            if checkBooleanExpression("%d=%d" % (randInt1, randInt3)):          # this must not be evaluated to True
                retVal = False
                break

            elif checkBooleanExpression("%d=%d" % (randInt3, randInt2)):        # this must not be evaluated to True
                retVal = False
                break

            elif not checkBooleanExpression("%d=%d" % (randInt2, randInt2)):    # this must be evaluated to True
                retVal = False
                break

            elif checkBooleanExpression("%d %d" % (randInt3, randInt2)):        # this must not be evaluated to True (invalid statement)
                retVal = False
                break

        if not retVal:
            warnMsg = "false positive or unexploitable injection point detected"
            logger.warn(warnMsg)

        kb.injection = popValue()

    return retVal

def checkSuhosinPatch(injection):
    """
    Checks for existence of Suhosin-patch (and alike) protection mechanism(s)
    """

    if injection.place == PLACE.GET:
        debugMsg = "checking for parameter length "
        debugMsg += "constrainting mechanisms"
        logger.debug(debugMsg)

        pushValue(kb.injection)

        kb.injection = injection
        randInt = randomInt()

        if not checkBooleanExpression("%d=%s%d" % (randInt, ' ' * SUHOSIN_MAX_VALUE_LENGTH, randInt)):
            warnMsg = "parameter length constrainting "
            warnMsg += "mechanism detected (e.g. Suhosin patch). "
            warnMsg += "Potential problems in enumeration phase can be expected"
            logger.warn(warnMsg)

        kb.injection = popValue()

def checkFilteredChars(injection):
    debugMsg = "checking for filtered characters"
    logger.debug(debugMsg)

    pushValue(kb.injection)

    kb.injection = injection
    randInt = randomInt()

    # all other techniques are already using parentheses in tests
    if len(injection.data) == 1 and PAYLOAD.TECHNIQUE.BOOLEAN in injection.data:
        if not checkBooleanExpression("(%d)=%d" % (randInt, randInt)):
            warnMsg = "it appears that some non-alphanumeric characters (i.e. ()) are "
            warnMsg += "filtered by the back-end server. There is a strong "
            warnMsg += "possibility that sqlmap won't be able to properly "
            warnMsg += "exploit this vulnerability"
            logger.warn(warnMsg)

    # inference techniques depend on character '>'
    if not any(_ in injection.data for _ in (PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.QUERY)):
        if not checkBooleanExpression("%d>%d" % (randInt+1, randInt)):
            warnMsg = "it appears that the character '>' is "
            warnMsg += "filtered by the back-end server. You are strongly "
            warnMsg += "advised to rerun with the '--tamper=between'"
            logger.warn(warnMsg)

    kb.injection = popValue()

def heuristicCheckSqlInjection(place, parameter):
    if kb.nullConnection:
        debugMsg = "heuristic check skipped because NULL connection used"
        logger.debug(debugMsg)
        return None

    origValue = conf.paramDict[place][parameter]
    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place

    prefix = ""
    suffix = ""
    randStr = ""

    if conf.prefix or conf.suffix:
        if conf.prefix:
            prefix = conf.prefix

        if conf.suffix:
            suffix = conf.suffix

    while randStr.count('\'') != 1 or randStr.count('\"') != 1:
        randStr = randomStr(length=10, alphabet=HEURISTIC_CHECK_ALPHABET)

    kb.heuristicMode = True

    payload = "%s%s%s" % (prefix, randStr, suffix)
    payload = agent.payload(place, parameter, newValue=payload)
    page, _, _ = Request.queryPage(payload, place, content=True, raise404=False)

    kb.heuristicPage = page
    kb.heuristicMode = False

    parseFilePaths(page)
    result = wasLastResponseDBMSError()

    infoMsg = "heuristic (basic) test shows that %s parameter " % paramType
    infoMsg += "'%s' might " % parameter

    def _(page):
        return any(_ in (page or "") for _ in FORMAT_EXCEPTION_STRINGS)

    casting = _(page) and not _(kb.originalPage)

    if not casting and not result and kb.dynamicParameter and origValue.isdigit():
        randInt = int(randomInt())
        payload = "%s%s%s" % (prefix, "%d-%d" % (int(origValue) + randInt, randInt), suffix)
        payload = agent.payload(place, parameter, newValue=payload, where=PAYLOAD.WHERE.REPLACE)
        result = Request.queryPage(payload, place, raise404=False)

        if not result:
            randStr = randomStr()
            payload = "%s%s%s" % (prefix, "%s.%d%s" % (origValue, random.randint(1, 9), randStr), suffix)
            payload = agent.payload(place, parameter, newValue=payload, where=PAYLOAD.WHERE.REPLACE)
            casting = Request.queryPage(payload, place, raise404=False)

    kb.heuristicTest = HEURISTIC_TEST.CASTED if casting else HEURISTIC_TEST.NEGATIVE if not result else HEURISTIC_TEST.POSITIVE

    if casting:
        errMsg = "possible %s casting " % ("integer" if origValue.isdigit() else "type")
        errMsg += "detected (e.g. \"$%s=intval($_REQUEST['%s'])\") " % (parameter, parameter)
        errMsg += "at the back-end web application"
        logger.error(errMsg)

        if kb.ignoreCasted is None:
            message = "do you want to skip those kind of cases (and save scanning time)? %s " % ("[Y/n]" if conf.multipleTargets else "[y/N]")
            kb.ignoreCasted = readInput(message, default='Y' if conf.multipleTargets else 'N', boolean=True)

    elif result:
        infoMsg += "be injectable"
        if Backend.getErrorParsedDBMSes():
            infoMsg += " (possible DBMS: '%s')" % Format.getErrorParsedDBMSes()
        logger.info(infoMsg)

    else:
        infoMsg += "not be injectable"
        logger.warn(infoMsg)

    kb.heuristicMode = True

    randStr1, randStr2 = randomStr(NON_SQLI_CHECK_PREFIX_SUFFIX_LENGTH), randomStr(NON_SQLI_CHECK_PREFIX_SUFFIX_LENGTH)
    value = "%s%s%s" % (randStr1, DUMMY_NON_SQLI_CHECK_APPENDIX, randStr2)
    payload = "%s%s%s" % (prefix, "'%s" % value, suffix)
    payload = agent.payload(place, parameter, newValue=payload)
    page, _, _ = Request.queryPage(payload, place, content=True, raise404=False)

    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place

    if value.lower() in (page or "").lower():
        infoMsg = "heuristic (XSS) test shows that %s parameter " % paramType
        infoMsg += "'%s' might be vulnerable to cross-site scripting attacks" % parameter
        logger.info(infoMsg)

    for match in re.finditer(FI_ERROR_REGEX, page or ""):
        if randStr1.lower() in match.group(0).lower():
            infoMsg = "heuristic (FI) test shows that %s parameter " % paramType
            infoMsg += "'%s' might be vulnerable to file inclusion attacks" % parameter
            logger.info(infoMsg)
            break

    kb.heuristicMode = False

    return kb.heuristicTest

def checkDynParam(place, parameter, value):
    """
    This function checks if the URL parameter is dynamic. If it is
    dynamic, the content of the page differs, otherwise the
    dynamicity might depend on another parameter.
    """

    if kb.redirectChoice:
        return None

    kb.matchRatio = None
    dynResult = None
    randInt = randomInt()

    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place

    infoMsg = "testing if %s parameter '%s' is dynamic" % (paramType, parameter)
    logger.info(infoMsg)

    try:
        payload = agent.payload(place, parameter, value, getUnicode(randInt))
        dynResult = Request.queryPage(payload, place, raise404=False)

        if not dynResult:
            infoMsg = "confirming that %s parameter '%s' is dynamic" % (paramType, parameter)
            logger.info(infoMsg)

            randInt = randomInt()
            payload = agent.payload(place, parameter, value, getUnicode(randInt))
            dynResult = Request.queryPage(payload, place, raise404=False)
    except SqlmapConnectionException:
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

    if firstPage and secondPage and any(len(_) > MAX_DIFFLIB_SEQUENCE_LENGTH for _ in (firstPage, secondPage)):
        ratio = None
    else:
        try:
            seqMatcher = getCurrentThreadData().seqMatcher
            seqMatcher.set_seq1(firstPage)
            seqMatcher.set_seq2(secondPage)
            ratio = seqMatcher.quick_ratio()
        except MemoryError:
            ratio = None

    if ratio is None:
        kb.skipSeqMatcher = True

    # In case of an intolerable difference turn on dynamicity removal engine
    elif ratio <= UPPER_RATIO_BOUND:
        findDynamicContent(firstPage, secondPage)

        count = 0
        while not Request.queryPage():
            count += 1

            if count > conf.retries:
                warnMsg = "target URL is too dynamic. "
                warnMsg += "Switching to '--text-only' "
                logger.warn(warnMsg)

                conf.textOnly = True
                return

            warnMsg = "target URL is heavily dynamic"
            warnMsg += ". sqlmap is going to retry the request"
            logger.critical(warnMsg)

            secondPage, _, _ = Request.queryPage(content=True)
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

    infoMsg = "testing if the target URL is stable"
    logger.info(infoMsg)

    firstPage = kb.originalPage  # set inside checkConnection()

    delay = 1 - (time.time() - (kb.originalPageTime or 0))
    delay = max(0, min(1, delay))
    time.sleep(delay)

    secondPage, _, _ = Request.queryPage(content=True, noteResponseTime=False, raise404=False)

    if kb.redirectChoice:
        return None

    kb.pageStable = (firstPage == secondPage)

    if kb.pageStable:
        if firstPage:
            infoMsg = "target URL is stable"
            logger.info(infoMsg)
        else:
            errMsg = "there was an error checking the stability of page "
            errMsg += "because of lack of content. Please check the "
            errMsg += "page request results (and probable errors) by "
            errMsg += "using higher verbosity levels"
            logger.error(errMsg)

    else:
        warnMsg = "target URL is not stable. sqlmap will base the page "
        warnMsg += "comparison on a sequence matcher. If no dynamic nor "
        warnMsg += "injectable parameters are detected, or in case of "
        warnMsg += "junk results, refer to user's manual paragraph "
        warnMsg += "'Page comparison' and provide a string or regular "
        warnMsg += "expression to match on"
        logger.warn(warnMsg)

        message = "how do you want to proceed? [(C)ontinue/(s)tring/(r)egex/(q)uit] "
        choice = readInput(message, default='C').upper()

        if choice == 'Q':
            raise SqlmapUserQuitException

        elif choice == 'S':
            showStaticWords(firstPage, secondPage)

            message = "please enter value for parameter 'string': "
            string = readInput(message)

            if string:
                conf.string = string

                if kb.nullConnection:
                    debugMsg = "turning off NULL connection "
                    debugMsg += "support because of string checking"
                    logger.debug(debugMsg)

                    kb.nullConnection = None
            else:
                errMsg = "Empty value supplied"
                raise SqlmapNoneDataException(errMsg)

        elif choice == 'R':
            message = "please enter value for parameter 'regex': "
            regex = readInput(message)

            if regex:
                conf.regex = regex

                if kb.nullConnection:
                    debugMsg = "turning off NULL connection "
                    debugMsg += "support because of regex checking"
                    logger.debug(debugMsg)

                    kb.nullConnection = None
            else:
                errMsg = "Empty value supplied"
                raise SqlmapNoneDataException(errMsg)

        else:
            checkDynamicContent(firstPage, secondPage)

    return kb.pageStable

def checkString():
    if not conf.string:
        return True

    infoMsg = "testing if the provided string is within the "
    infoMsg += "target URL page content"
    logger.info(infoMsg)

    page, headers, _ = Request.queryPage(content=True)
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

    page, headers, _ = Request.queryPage(content=True)
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

    if any((conf.string, conf.notString, conf.regexp, conf.dummy, conf.offline, conf.skipWaf)):
        return None

    _ = hashDBRetrieve(HASHDB_KEYS.CHECK_WAF_RESULT, True)
    if _ is not None:
        if _:
            warnMsg = "previous heuristics detected that the target "
            warnMsg += "is protected by some kind of WAF/IPS/IDS"
            logger.critical(warnMsg)
        return _

    infoMsg = "checking if the target is protected by "
    infoMsg += "some kind of WAF/IPS/IDS"
    logger.info(infoMsg)

    retVal = False
    payload = "%d %s" % (randomInt(), IDS_WAF_CHECK_PAYLOAD)

    value = "" if not conf.parameters.get(PLACE.GET) else conf.parameters[PLACE.GET] + DEFAULT_GET_POST_DELIMITER
    value += agent.addPayloadDelimiters("%s=%s" % (randomStr(), payload))

    pushValue(conf.timeout)
    conf.timeout = IDS_WAF_CHECK_TIMEOUT

    try:
        retVal = Request.queryPage(place=PLACE.GET, value=value, getRatioValue=True, noteResponseTime=False, silent=True)[1] < IDS_WAF_CHECK_RATIO
    except SqlmapConnectionException:
        retVal = True
    finally:
        kb.matchRatio = None
        conf.timeout = popValue()

    if retVal:
        warnMsg = "heuristics detected that the target "
        warnMsg += "is protected by some kind of WAF/IPS/IDS"
        logger.critical(warnMsg)

        if not conf.identifyWaf:
            message = "do you want sqlmap to try to detect backend "
            message += "WAF/IPS/IDS? [y/N] "

            if readInput(message, default='N', boolean=True):
                conf.identifyWaf = True

        if conf.timeout == defaults.timeout:
            logger.warning("dropping timeout to %d seconds (i.e. '--timeout=%d')" % (IDS_WAF_CHECK_TIMEOUT, IDS_WAF_CHECK_TIMEOUT))
            conf.timeout = IDS_WAF_CHECK_TIMEOUT

    hashDBWrite(HASHDB_KEYS.CHECK_WAF_RESULT, retVal, True)

    return retVal

def identifyWaf():
    if not conf.identifyWaf:
        return None

    if not kb.wafFunctions:
        setWafFunctions()

    kb.testMode = True

    infoMsg = "using WAF scripts to detect "
    infoMsg += "backend WAF/IPS/IDS protection"
    logger.info(infoMsg)

    @cachedmethod
    def _(*args, **kwargs):
        page, headers, code = None, None, None
        try:
            pushValue(kb.redirectChoice)
            kb.redirectChoice = REDIRECTION.NO
            if kwargs.get("get"):
                kwargs["get"] = urlencode(kwargs["get"])
            kwargs["raise404"] = False
            kwargs["silent"] = True
            page, headers, code = Request.getPage(*args, **kwargs)
        except Exception:
            pass
        finally:
            kb.redirectChoice = popValue()
        return page or "", headers or {}, code

    retVal = []

    for function, product in kb.wafFunctions:
        try:
            logger.debug("checking for WAF/IPS/IDS product '%s'" % product)
            found = function(_)
        except Exception, ex:
            errMsg = "exception occurred while running "
            errMsg += "WAF script for '%s' ('%s')" % (product, getSafeExString(ex))
            logger.critical(errMsg)

            found = False

        if found:
            errMsg = "WAF/IPS/IDS identified as '%s'" % product
            logger.critical(errMsg)

            retVal.append(product)

    if retVal:
        message = "are you sure that you want to "
        message += "continue with further target testing? [y/N] "
        choice = readInput(message, default='N', boolean=True)

        if not conf.tamper:
            warnMsg = "please consider usage of tamper scripts (option '--tamper')"
            singleTimeWarnMessage(warnMsg)

        if not choice:
            raise SqlmapUserQuitException
    else:
        warnMsg = "WAF/IPS/IDS product hasn't been identified"
        logger.warn(warnMsg)

    kb.testType = None
    kb.testMode = False

    return retVal

def checkNullConnection():
    """
    Reference: http://www.wisec.it/sectou.php?id=472f952d79293
    """

    if conf.data:
        return False

    infoMsg = "testing NULL connection to the target URL"
    logger.info(infoMsg)

    try:
        pushValue(kb.pageCompress)
        kb.pageCompress = False

        page, headers, _ = Request.getPage(method=HTTPMETHOD.HEAD)

        if not page and HTTP_HEADER.CONTENT_LENGTH in (headers or {}):
            kb.nullConnection = NULLCONNECTION.HEAD

            infoMsg = "NULL connection is supported with HEAD method (Content-Length)"
            logger.info(infoMsg)
        else:
            page, headers, _ = Request.getPage(auxHeaders={HTTP_HEADER.RANGE: "bytes=-1"})

            if page and len(page) == 1 and HTTP_HEADER.CONTENT_RANGE in (headers or {}):
                kb.nullConnection = NULLCONNECTION.RANGE

                infoMsg = "NULL connection is supported with GET method (Range)"
                infoMsg += "'%s'" % kb.nullConnection
                logger.info(infoMsg)
            else:
                _, headers, _ = Request.getPage(skipRead = True)

                if HTTP_HEADER.CONTENT_LENGTH in (headers or {}):
                    kb.nullConnection = NULLCONNECTION.SKIP_READ

                    infoMsg = "NULL connection is supported with 'skip-read' method"
                    logger.info(infoMsg)

    except SqlmapConnectionException, ex:
        errMsg = getSafeExString(ex)
        raise SqlmapConnectionException(errMsg)

    finally:
        kb.pageCompress = popValue()

    return kb.nullConnection is not None

def checkConnection(suppressOutput=False):
    if not any((conf.proxy, conf.tor, conf.dummy, conf.offline)):
        try:
            debugMsg = "resolving hostname '%s'" % conf.hostname
            logger.debug(debugMsg)
            socket.getaddrinfo(conf.hostname, None)
        except socket.gaierror:
            errMsg = "host '%s' does not exist" % conf.hostname
            raise SqlmapConnectionException(errMsg)
        except socket.error, ex:
            errMsg = "problem occurred while "
            errMsg += "resolving a host name '%s' ('%s')" % (conf.hostname, getSafeExString(ex))
            raise SqlmapConnectionException(errMsg)

    if not suppressOutput and not conf.dummy and not conf.offline:
        infoMsg = "testing connection to the target URL"
        logger.info(infoMsg)

    try:
        kb.originalPageTime = time.time()
        page, headers, _ = Request.queryPage(content=True, noteResponseTime=False)
        kb.originalPage = kb.pageTemplate = page

        kb.errorIsNone = False

        if not kb.originalPage and wasLastResponseHTTPError():
            errMsg = "unable to retrieve page content"
            raise SqlmapConnectionException(errMsg)
        elif wasLastResponseDBMSError():
            warnMsg = "there is a DBMS error found in the HTTP response body "
            warnMsg += "which could interfere with the results of the tests"
            logger.warn(warnMsg)
        elif wasLastResponseHTTPError():
            warnMsg = "the web server responded with an HTTP error code (%d) " % getLastRequestHTTPError()
            warnMsg += "which could interfere with the results of the tests"
            logger.warn(warnMsg)
        else:
            kb.errorIsNone = True

    except SqlmapConnectionException, ex:
        if conf.ipv6:
            warnMsg = "check connection to a provided "
            warnMsg += "IPv6 address with a tool like ping6 "
            warnMsg += "(e.g. 'ping6 -I eth0 %s') " % conf.hostname
            warnMsg += "prior to running sqlmap to avoid "
            warnMsg += "any addressing issues"
            singleTimeWarnMessage(warnMsg)

        if any(code in kb.httpErrorCodes for code in (httplib.NOT_FOUND, )):
            errMsg = getSafeExString(ex)
            logger.critical(errMsg)

            if conf.multipleTargets:
                return False

            msg = "it is not recommended to continue in this kind of cases. Do you want to quit and make sure that everything is set up properly? [Y/n] "
            if readInput(msg, default='Y', boolean=True):
                raise SqlmapSilentQuitException
            else:
                kb.ignoreNotFound = True
        else:
            raise

    return True

def checkInternet():
    content = Request.getPage(url=CHECK_INTERNET_ADDRESS, checking=True)[0]
    return CHECK_INTERNET_VALUE in (content or "")

def setVerbosity():  # Cross-linked function
    raise NotImplementedError

def setWafFunctions():  # Cross-linked function
    raise NotImplementedError
