#!/usr/bin/env python

"""
$Id$

Copyright (c) 2006-2010 sqlmap developers (http://sqlmap.sourceforge.net/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.controller.action import action
from lib.controller.checks import checkSqlInjection
from lib.controller.checks import heuristicCheckSqlInjection
from lib.controller.checks import checkDynParam
from lib.controller.checks import checkStability
from lib.controller.checks import checkString
from lib.controller.checks import checkRegexp
from lib.controller.checks import checkConnection
from lib.controller.checks import checkNullConnection
from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import getUnicode
from lib.core.common import paramToDict
from lib.core.common import parseTargetUrl
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.dump import dumper
from lib.core.enums import HTTPMETHOD
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import exceptionsTuple
from lib.core.exception import sqlmapNotVulnerableException
from lib.core.exception import sqlmapSilentQuitException
from lib.core.exception import sqlmapValueException
from lib.core.exception import sqlmapUserQuitException
from lib.core.session import setInjection
from lib.core.target import initTargetEnv
from lib.core.target import setupTargetEnv

def __selectInjection():
    """
    Selection function for injection place, parameters and type.
    """

    points = []

    for i in xrange(0, len(kb.injections)):
        place = kb.injections[i].place
        parameter = kb.injections[i].parameter
        ptype = kb.injections[i].ptype

        point = (place, parameter, ptype)

        if point not in points:
            points.append(point)

    if len(points) == 1:
        kb.injection = kb.injections[0]

    elif len(points) > 1:
        message = "there were multiple injection points, please select "
        message += "the one to use for following injections:\n"

        points = []

        for i in xrange(0, len(kb.injections)):
            place = kb.injections[i].place
            parameter = kb.injections[i].parameter
            ptype = kb.injections[i].ptype
            point = (place, parameter, ptype)

            if point not in points:
                points.append(point)
                ptype = PAYLOAD.PARAMETER[ptype] if isinstance(ptype, int) else ptype

                message += "[%d] place: %s, parameter: " % (i, place)
                message += "%s, type: %s" % (parameter, ptype)

                if i == 0:
                    message += " (default)"

                message += "\n"

        message += "[q] Quit"
        select = readInput(message, default="0")

        if select.isdigit() and int(select) < len(kb.injections) and int(select) >= 0:
            index = int(select)
        elif select[0] in ( "Q", "q" ):
            raise sqlmapUserQuitException
        else:
            errMsg = "invalid choice"
            raise sqlmapValueException, errMsg

        kb.injection = kb.injections[index]

def __formatInjection(inj):
    data = "Place: %s\n" % inj.place
    data += "Parameter: %s\n" % inj.parameter

    for stype, sdata in inj.data.items():
        data += "    Type: %s\n" % PAYLOAD.SQLINJECTION[stype]
        data += "    Title: %s\n" % sdata.title
        data += "    Payload: %s\n\n" % sdata.payload

    return data

def __showInjections():
    header = "sqlmap identified the following injection points "
    header += "with %d HTTP(s) requests" % kb.testQueryCount
    data = ""

    for inj in kb.injections:
        data += __formatInjection(inj)

    data = data.rstrip("\n")

    dumper.technic(header, data)

def __saveToSessionFile():
    for inj in kb.injections:
        if inj.place is None or inj.parameter is None:
            continue

        setInjection(inj)

def start():
    """
    This function calls a function that performs checks on both URL
    stability and all GET, POST, Cookie and User-Agent parameters to
    check if they are dynamic and SQL injection affected
    """

    if not conf.start:
        return False

    if conf.direct:
        initTargetEnv()
        setupTargetEnv()
        action()
        return True

    if conf.url and not conf.forms:
        kb.targetUrls.add(( conf.url, conf.method, conf.data, conf.cookie ))

    if conf.configFile and not kb.targetUrls:
        errMsg  = "you did not edit the configuration file properly, set "
        errMsg += "the target url, list of targets or google dork"
        logger.error(errMsg)
        return False

    if kb.targetUrls and len(kb.targetUrls) > 1:
        infoMsg = "sqlmap got a total of %d targets" % len(kb.targetUrls)
        logger.info(infoMsg)

    hostCount             = 0
    cookieStr             = ""
    setCookieAsInjectable = True

    for targetUrl, targetMethod, targetData, targetCookie in kb.targetUrls:
        try:
            conf.url    = targetUrl
            conf.method = targetMethod
            conf.data   = targetData
            conf.cookie = targetCookie
            injData     = []

            initTargetEnv()
            parseTargetUrl()

            testSqlInj = False
            if PLACE.GET in conf.parameters:
                for parameter in re.findall(r"([^=]+)=[^&]+&?", conf.parameters[PLACE.GET]):
                    paramKey = (conf.hostname, conf.path, PLACE.GET, parameter)
                    if paramKey not in kb.testedParams:
                        testSqlInj = True
                        break
            else:
                paramKey = (conf.hostname, conf.path, None, None)
                if paramKey not in kb.testedParams:
                    testSqlInj = True

            if not testSqlInj:
                infoMsg = "skipping '%s'" % targetUrl
                logger.info(infoMsg)
                continue

            if conf.multipleTargets:
                hostCount += 1
                if conf.forms:
                    message = "[#%d] form:\n%s %s" % (hostCount, conf.method or HTTPMETHOD.GET, targetUrl)
                else:
                    message = "%s %d:\n%s %s" % ("url", hostCount, conf.method or HTTPMETHOD.GET, targetUrl)

                if conf.cookie:
                    message += "\nCookie: %s" % conf.cookie

                if conf.data:
                    message += "\nPOST data: %s" % repr(conf.data) if conf.data else ""

                if conf.forms:
                    if conf.method == HTTPMETHOD.GET and targetUrl.find("?") == -1:
                        continue

                    message += "\ndo you want to test this form? [Y/n/q] "
                    test = readInput(message, default="Y")

                    if not test or test[0] in ("y", "Y"):
                        if conf.method == HTTPMETHOD.POST:
                            message = "Edit POST data [default: %s]: " % (conf.data if conf.data else "")
                            conf.data = readInput(message, default=conf.data)

                        elif conf.method == HTTPMETHOD.GET:
                            if conf.url.find("?") > -1:
                                firstPart = conf.url[:conf.url.find("?")]
                                secondPart = conf.url[conf.url.find("?")+1:]
                                message = "Edit GET data [default: %s]: " % secondPart
                                test = readInput(message, default=secondPart)
                                conf.url = "%s?%s" % (firstPart, test)

                    elif test[0] in ("n", "N"):
                        continue
                    elif test[0] in ("q", "Q"):
                        break

                else:
                    message += "\ndo you want to test this url? [Y/n/q]"
                    test = readInput(message, default="Y")

                    if not test or test[0] in ("y", "Y"):
                        pass
                    elif test[0] in ("n", "N"):
                        continue
                    elif test[0] in ("q", "Q"):
                        break

                    logMsg = "testing url %s" % targetUrl
                    logger.info(logMsg)

            setupTargetEnv()

            if not checkConnection(suppressOutput=conf.forms) or not checkString() or not checkRegexp():
                continue

            if conf.nullConnection:
                checkNullConnection()

            if not conf.dropSetCookie and conf.cj:
                for _, cookie in enumerate(conf.cj):
                    cookie = getUnicode(cookie)
                    index  = cookie.index(" for ")

                    cookieStr += "%s;" % cookie[8:index]

                if cookieStr:
                    cookieStr = cookieStr[:-1]

                    if PLACE.COOKIE in conf.parameters:
                        message  = "you provided an HTTP Cookie header value. "
                        message += "The target url provided its own Cookie within "
                        message += "the HTTP Set-Cookie header. Do you want to "
                        message += "continue using the HTTP Cookie values that "
                        message += "you provided? [Y/n] "
                        test = readInput(message, default="Y")

                        if not test or test[0] in ("y", "Y"):
                            setCookieAsInjectable = False

                    if setCookieAsInjectable:
                        conf.httpHeaders.append(("Cookie", cookieStr))
                        conf.parameters[PLACE.COOKIE] = cookieStr
                        __paramDict = paramToDict(PLACE.COOKIE, cookieStr)

                        if __paramDict:
                            conf.paramDict[PLACE.COOKIE] = __paramDict
                            # TODO: consider the following line in __setRequestParams()
                            __testableParameters = True

            if (len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None)) \
                and (kb.injection.place is None or kb.injection.parameter is None):
                if not conf.string and not conf.regexp and not conf.eRegexp:
                    # NOTE: this is not needed anymore, leaving only to display
                    # a warning message to the user in case the page is not stable
                    checkStability()

                # Do a little prioritization reorder of a testable parameter list 
                parameters = conf.parameters.keys()

                for place in (PLACE.URI, PLACE.POST, PLACE.GET):
                    if place in parameters:
                        parameters.remove(place)
                        parameters.insert(0, place)

                proceed = True

                for place in parameters:
                    # Test User-Agent header only if --level >= 4
                    condition = (place == "User-Agent" and conf.level < 4)
                    # Test Cookie header only if --level >= 3
                    condition |= (place == "Cookie" and conf.level < 3)

                    if condition:
                        continue

                    if not conf.paramDict.has_key(place):
                        continue

                    if not proceed:
                        break

                    paramDict = conf.paramDict[place]
                    for parameter, value in paramDict.items():
                        testSqlInj = True

                        paramKey = (conf.hostname, conf.path, place, parameter)

                        if paramKey in kb.testedParams:
                            testSqlInj = False

                            infoMsg = "skipping previously processed %s parameter '%s'" % (place, parameter)
                            logger.info(infoMsg)

                        # Avoid dinamicity test if the user provided the
                        # parameter manually
                        elif parameter in conf.testParameter:
                            pass

                        elif not checkDynParam(place, parameter, value):
                            warnMsg = "%s parameter '%s' is not dynamic" % (place, parameter)
                            logger.warn(warnMsg)

                        else:
                            logMsg = "%s parameter '%s' is dynamic" % (place, parameter)
                            logger.info(logMsg)

                        kb.testedParams.add(paramKey)

                        if testSqlInj:
                            check = heuristicCheckSqlInjection(place, parameter, value)
                            if not check and conf.scriptKiddie:
                                continue

                            logMsg  = "testing sql injection on %s " % place
                            logMsg += "parameter '%s'" % parameter
                            logger.info(logMsg)

                            injection = checkSqlInjection(place, parameter, value)

                            if injection is not None and injection.place is not None:
                                kb.injections.append(injection)

                                msg = "%s parameter '%s' " % (injection.place, injection.parameter)
                                msg += "is vulnerable. Do you want to keep testing the others? [y/N] "
                                test = readInput(msg, default="N")

                                if test[0] in ("n", "N"):
                                    proceed = False
                                    break
                            else:
                                warnMsg  = "%s parameter '%s' is not " % (place, parameter)
                                warnMsg += "injectable"
                                logger.warn(warnMsg)

            if len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None):
                errMsg = "all parameters are not injectable, try "
                errMsg += "a higher --level"
                raise sqlmapNotVulnerableException, errMsg
            else:
                __saveToSessionFile()
                __showInjections()
                __selectInjection()

            if kb.injection.place is not None and kb.injection.parameter is not None:
                if conf.multipleTargets:
                    message = "do you want to exploit this SQL injection? [Y/n] "
                    exploit = readInput(message, default="Y")

                    condition = not exploit or exploit[0] in ("y", "Y")
                else:
                    condition = True

                if condition:
                    action()

        except KeyboardInterrupt:
            if conf.multipleTargets:
                warnMsg = "Ctrl+C detected in multiple target mode"
                logger.warn(warnMsg)

                message = "do you want to skip to the next target in list? [Y/n/q]"
                test = readInput(message, default="Y")

                if not test or test[0] in ("y", "Y"):
                    pass
                elif test[0] in ("n", "N"):
                    return False
                elif test[0] in ("q", "Q"):
                    raise sqlmapUserQuitException
            else:
                raise

        except sqlmapUserQuitException:
            raise

        except sqlmapSilentQuitException:
            raise

        except exceptionsTuple, e:
            e = getUnicode(e)

            if conf.multipleTargets:
                e += ", skipping to the next %s" % ("form" if conf.forms else "url")
                logger.error(e)
            else:
                logger.critical(e)
                return False

    if conf.loggedToOut:
        logger.info("Fetched data logged to text files under '%s'" % conf.outputPath)

    return True
